"""
Enhanced Model Inference Module

Provides inference using the retrained ML models with:
- Multi-scanner consensus integration
- Transformer-based risk classification
- GNN-based code graph analysis
- Ensemble predictions combining all models

This module integrates with the CLI to provide ML-enhanced vulnerability detection.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import torch
from torch import nn


@dataclass
class PredictionResult:
    """Result from ML model prediction."""

    sample_id: str
    risk_score: float  # 0.0 to 1.0
    risk_label: str  # "HIGH_RISK", "MEDIUM_RISK", "LOW_RISK"
    predicted_category: str
    category_scores: dict[str, float]
    confidence: float
    model_source: str  # "transformer", "gnn", "ensemble"

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "risk_score": self.risk_score,
            "risk_label": self.risk_label,
            "predicted_category": self.predicted_category,
            "category_scores": self.category_scores,
            "confidence": self.confidence,
            "model_source": self.model_source,
        }


class EnhancedInferenceEngine:
    """
    Inference engine that combines multiple ML models for vulnerability detection.

    Models:
    - Transformer: Token-based classification
    - GNN: Graph-based code analysis
    - Ensemble: Combines Transformer + GNN with learned weights
    """

    def __init__(
        self,
        artifacts_dir: Path | None = None,
        device: str = "cpu",
    ):
        self.artifacts_dir = artifacts_dir or Path("artifacts/dl")
        self.device = torch.device(device)

        self._transformer_model = None
        self._transformer_vocab = None
        self._transformer_categories = None
        self._transformer_temperature = 1.0

        self._gnn_model = None
        self._gnn_categories = None

        # Binary classifier (simpler, more accurate)
        self._binary_model = None
        self._binary_vocab = None

        # Ensemble model components
        self._ensemble_weights = None  # (transformer_weight, gnn_weight)
        self._ensemble_temperature = 1.0

        self._models_loaded = False

    def _load_models(self) -> None:
        """Lazy-load the ML models."""
        if self._models_loaded:
            return

        # Try to load transformer model
        transformer_paths = [
            self.artifacts_dir / "transformer_enhanced.pt",
            self.artifacts_dir / "transformer_v1.pt",
            Path("artifacts/models/transformer_v2.pt"),
        ]

        for path in transformer_paths:
            if path.exists():
                try:
                    checkpoint = torch.load(path, map_location=self.device, weights_only=False)
                    self._transformer_categories = checkpoint.get("category_vocab", [])
                    vocab_data = checkpoint.get("vocab", {})

                    # Handle different vocab formats:
                    # 1. train_transformer.py saves vocab.token_to_id directly
                    # 2. train_pipeline.py saves vocab.to_dict() with nested structure
                    if "token_to_id" in vocab_data:
                        # Nested format from train_pipeline.py
                        self._transformer_vocab = vocab_data["token_to_id"]
                        vocab_size = vocab_data.get("size", len(self._transformer_vocab))
                    else:
                        # Direct token_to_id dict from train_transformer.py
                        self._transformer_vocab = vocab_data
                        vocab_size = len(vocab_data)

                    self._transformer_temperature = checkpoint.get("temperature_risk", 1.0)

                    # Rebuild model using "small" config (no HuggingFace dependency)
                    from ml.models.transformer import build_model

                    self._transformer_model = build_model(
                        model_name="small",  # Use small config for offline loading
                        num_categories=len(self._transformer_categories),
                        vocab_size=vocab_size,
                        max_len=checkpoint.get("max_len", 256),
                        random_init=True,
                    )
                    self._transformer_model.load_state_dict(checkpoint["model_state_dict"])
                    self._transformer_model.to(self.device)
                    self._transformer_model.eval()
                    break
                except Exception:
                    continue

        # Try to load GNN model
        gnn_paths = [
            self.artifacts_dir / "gnn_enhanced.pt",
            self.artifacts_dir / "gnn_v1.pt",
            Path("artifacts/models/gnn_v2.pt"),
        ]

        for path in gnn_paths:
            if path.exists():
                try:
                    checkpoint = torch.load(path, map_location=self.device)
                    self._gnn_categories = checkpoint.get("category_vocab", [])

                    from ml.models.gnn import GraphClassifier

                    self._gnn_model = GraphClassifier(
                        num_categories=len(self._gnn_categories),
                        hidden_dim=checkpoint.get("hidden_dim", 128),
                        num_layers=checkpoint.get("layers", 2),
                        dropout=checkpoint.get("dropout", 0.1),
                    )
                    self._gnn_model.load_state_dict(checkpoint["model_state_dict"])
                    self._gnn_model.to(self.device)
                    self._gnn_model.eval()
                    break
                except Exception:
                    continue

        # Load ensemble weights
        ensemble_path = self.artifacts_dir / "ensemble_enhanced.pt"
        if ensemble_path.exists():
            try:
                checkpoint = torch.load(ensemble_path, map_location=self.device)
                self._ensemble_weights = checkpoint.get("weights", (0.5, 0.5))
                self._ensemble_temperature = checkpoint.get("temperature", 1.0)
            except Exception:
                pass

        # Load binary classifier (preferred for accuracy)
        binary_path = self.artifacts_dir / "binary_classifier.pt"
        if binary_path.exists():
            try:
                from ml.train_binary_focused import load_binary_model

                self._binary_model, self._binary_vocab = load_binary_model(
                    binary_path, device=str(self.device)
                )
            except Exception:
                pass

        self._models_loaded = True

    def predict_risk(
        self,
        code_snippet: str,
        category_hint: str | None = None,
        scanner_sources: list[str] | None = None,
        consensus_score: float | None = None,
    ) -> PredictionResult:
        """
        Predict risk score for a code snippet.

        Args:
            code_snippet: The code to analyze
            category_hint: Optional category from scanners
            scanner_sources: List of scanners that flagged this
            consensus_score: Pre-computed consensus score

        Returns:
            PredictionResult with risk assessment
        """
        self._load_models()

        # Tokenize code
        tokens = self._tokenize(code_snippet)

        # Use binary classifier if available (most accurate)
        binary_score = None
        if self._binary_model is not None:
            from ml.train_binary_focused import predict_vulnerability

            binary_score = predict_vulnerability(
                code_snippet, self._binary_model, self._binary_vocab
            )

        # Get transformer prediction if available
        transformer_score = None
        transformer_category = None
        if self._transformer_model is not None:
            transformer_score, transformer_category = self._predict_transformer(tokens)

        # Get GNN prediction if available
        gnn_score = None
        if self._gnn_model is not None:
            gnn_score = self._predict_gnn(code_snippet)

        # Priority: binary > ensemble > transformer > gnn
        if binary_score is not None:
            model_score = binary_score
            model_source = "binary_classifier"
        elif (
            transformer_score is not None
            and gnn_score is not None
            and self._ensemble_weights is not None
        ):
            t_weight, g_weight = self._ensemble_weights
            # Apply temperature scaling
            t_calibrated = transformer_score / self._ensemble_temperature
            g_calibrated = gnn_score / self._ensemble_temperature
            model_score = t_weight * t_calibrated + g_weight * g_calibrated
            model_score = max(0.0, min(1.0, model_score))  # Clamp to [0, 1]
            model_source = "ensemble"
        elif transformer_score is not None:
            model_score = transformer_score
            model_source = "transformer"
        elif gnn_score is not None:
            model_score = gnn_score
            model_source = "gnn"
        else:
            model_score = None
            model_source = None

        # Combine with consensus if available
        if consensus_score is not None and model_score is not None:
            # Weight: 60% ML model, 40% consensus
            final_score = 0.6 * model_score + 0.4 * consensus_score
            if model_source:
                model_source = f"{model_source}+consensus"
        elif model_score is not None:
            final_score = model_score
        elif consensus_score is not None:
            final_score = consensus_score
            model_source = "consensus"
        else:
            final_score = 0.5
            model_source = "fallback"

        # Boost score if multiple scanners agree
        if scanner_sources and len(scanner_sources) >= 3:
            final_score = min(1.0, final_score * 1.2)

        # Determine risk label
        if final_score >= 0.7:
            risk_label = "HIGH_RISK"
        elif final_score >= 0.4:
            risk_label = "MEDIUM_RISK"
        else:
            risk_label = "LOW_RISK"

        # Determine category
        predicted_category = category_hint or transformer_category or "unknown"

        # Compute confidence
        confidence = self._compute_confidence(
            transformer_score,
            consensus_score,
            scanner_sources,
        )

        return PredictionResult(
            sample_id=self._generate_sample_id(code_snippet),
            risk_score=final_score,
            risk_label=risk_label,
            predicted_category=predicted_category,
            category_scores={predicted_category: final_score} if predicted_category else {},
            confidence=confidence,
            model_source=model_source,
        )

    def predict_batch(
        self,
        findings: list[dict[str, Any]],
    ) -> list[PredictionResult]:
        """
        Predict risk for a batch of findings.

        Args:
            findings: List of finding dictionaries with code_snippet, category, etc.

        Returns:
            List of PredictionResults
        """
        results = []

        for finding in findings:
            result = self.predict_risk(
                code_snippet=finding.get("code_snippet", finding.get("code", "")),
                category_hint=finding.get("category"),
                scanner_sources=finding.get("scanner_sources", []),
                consensus_score=finding.get("consensus_score"),
            )
            results.append(result)

        return results

    def _tokenize(self, code: str) -> list[str]:
        """Tokenize code for the transformer model."""
        import re

        tokens = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*|[0-9]+|[^\s\w]", code)
        return tokens[:256]

    def _predict_transformer(self, tokens: list[str]) -> tuple[float, str]:
        """Get prediction from transformer model."""
        if self._transformer_model is None:
            return None, None

        max_len = 256

        # Special token IDs
        PAD_ID = 0
        CLS_ID = 1
        SEP_ID = 2
        UNK_ID = 3

        # Build token_to_id lookup from vocabulary
        # After loading, self._transformer_vocab is already the token_to_id dict
        if isinstance(self._transformer_vocab, dict):
            token_to_id = self._transformer_vocab
        else:
            token_to_id = {}

        # Encode tokens with proper vocabulary lookup
        token_ids = [CLS_ID]  # Start with CLS token
        for token in tokens[: max_len - 2]:  # Leave room for CLS and SEP
            token_ids.append(token_to_id.get(token, UNK_ID))
        token_ids.append(SEP_ID)  # End with SEP token

        attention = [1] * len(token_ids)

        # Pad to max_len
        while len(token_ids) < max_len:
            token_ids.append(PAD_ID)
            attention.append(0)

        input_ids = torch.tensor([token_ids], dtype=torch.long, device=self.device)
        attention_mask = torch.tensor([attention], dtype=torch.long, device=self.device)

        with torch.no_grad():
            cat_logits, risk_logit = self._transformer_model(
                input_ids=input_ids,
                attention_mask=attention_mask,
            )

            # Apply temperature calibration for risk score
            # Cap temperature to prevent over-smoothing (min 0.1, max 10.0)
            temp = max(0.1, min(10.0, self._transformer_temperature))
            calibrated_logit = risk_logit / temp
            risk_score = torch.sigmoid(calibrated_logit).item()

            # Use raw logit if temperature is unreasonable
            if self._transformer_temperature > 100:
                risk_score = torch.sigmoid(risk_logit).item()

            cat_probs = torch.sigmoid(cat_logits).squeeze(0)

            if self._transformer_categories:
                best_cat_idx = cat_probs.argmax().item()
                best_category = self._transformer_categories[best_cat_idx]
            else:
                best_category = "unknown"

        return risk_score, best_category

    def _predict_gnn(self, code: str) -> float | None:
        """Get risk prediction from GNN model."""
        if self._gnn_model is None:
            return None

        try:
            import ast

            tree = ast.parse(code)
        except (SyntaxError, ValueError):
            # Code doesn't parse as Python - skip GNN
            return None

        # Build graph from AST
        try:
            from ml.train_gnn import build_graph_from_ast

            graph = build_graph_from_ast(tree)

            if graph is None or graph.num_nodes == 0:
                return None

            graph = graph.to(self.device)

            with torch.no_grad():
                cat_logits, risk_logit = self._gnn_model(
                    graph.x,
                    graph.edge_index,
                    torch.zeros(graph.num_nodes, dtype=torch.long, device=self.device),
                )
                risk_score = torch.sigmoid(risk_logit).mean().item()

            return risk_score
        except Exception:
            return None

    def _compute_confidence(
        self,
        transformer_score: float | None,
        consensus_score: float | None,
        scanner_sources: list[str] | None,
    ) -> float:
        """Compute overall prediction confidence."""
        confidence = 0.5

        # Model agreement boosts confidence
        if transformer_score is not None and consensus_score is not None:
            # If both agree (both high or both low), increase confidence
            agreement = 1.0 - abs(transformer_score - consensus_score)
            confidence = 0.5 + 0.3 * agreement

        # More scanners = higher confidence
        if scanner_sources:
            scanner_boost = min(0.2, len(scanner_sources) * 0.05)
            confidence += scanner_boost

        return min(1.0, confidence)

    def _generate_sample_id(self, code: str) -> str:
        """Generate a sample ID from code."""
        import hashlib

        return hashlib.sha256(code.encode()).hexdigest()[:16]

    @property
    def is_available(self) -> bool:
        """Check if any ML models are available."""
        self._load_models()
        return self._transformer_model is not None or self._gnn_model is not None


@lru_cache(maxsize=1)
def get_inference_engine(artifacts_dir: str | None = None) -> EnhancedInferenceEngine:
    """Get or create the inference engine singleton."""
    return EnhancedInferenceEngine(
        artifacts_dir=Path(artifacts_dir) if artifacts_dir else None,
    )


def enhance_findings_with_ml(
    findings: list[dict[str, Any]],
    artifacts_dir: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Enhance scanner findings with ML predictions.

    Args:
        findings: List of scanner findings
        artifacts_dir: Path to model artifacts

    Returns:
        Findings enhanced with ML predictions
    """
    engine = EnhancedInferenceEngine(artifacts_dir=artifacts_dir)

    if not engine.is_available:
        # No models available, return findings as-is
        return findings

    enhanced = []
    for finding in findings:
        prediction = engine.predict_risk(
            code_snippet=finding.get("code_snippet", finding.get("code", "")),
            category_hint=finding.get("category"),
            scanner_sources=finding.get("scanner_sources", []),
            consensus_score=finding.get("consensus_score"),
        )

        # Add ML predictions to finding
        enhanced_finding = {
            **finding,
            "ml_risk_score": prediction.risk_score,
            "ml_risk_label": prediction.risk_label,
            "ml_confidence": prediction.confidence,
            "ml_model_source": prediction.model_source,
        }
        enhanced.append(enhanced_finding)

    return enhanced
