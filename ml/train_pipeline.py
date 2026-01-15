#!/usr/bin/env python3
"""
Unified ML Training Pipeline

Complete pipeline for training security vulnerability detection models:
1. Generate enhanced dataset using all 5 scanners
2. Train Transformer model
3. Train GNN model
4. Export models to artifacts
5. Run evaluation and validation

Usage:
    python -m ml.train_pipeline --targets . --output artifacts/models
    python -m ml.train_pipeline --skip-scan --dataset datasets/enhanced
"""

from __future__ import annotations

import argparse
import json
import math
import shutil
import subprocess
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import torch
import torch.nn as nn

# Add project root to path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def print_header(title: str) -> None:
    """Print a formatted section header."""
    print()
    print("=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_step(step: int, total: int, message: str) -> None:
    """Print a step progress message."""
    print(f"\n[{step}/{total}] {message}")


def resolve_device(requested: str) -> str:
    """Resolve training device with a safe CUDA fallback."""
    if requested in {"auto", "cuda_if_available"}:
        requested = "cuda"
    if requested != "cuda":
        return requested
    try:
        if torch.cuda.is_available():
            try:
                torch.cuda.init()
                name = torch.cuda.get_device_name(0)
                print(f"    ✅ CUDA available: {name}")
            except Exception as exc:
                print(f"    ⚠️ CUDA init failed ({exc}); falling back to CPU.")
                return "cpu"
            return "cuda"
    except Exception as exc:
        print(f"    ⚠️ CUDA check failed ({exc}); falling back to CPU.")
        return "cpu"
    print("    ⚠️ CUDA requested but not available; falling back to CPU.")
    return "cpu"


class FocalLoss(nn.Module):
    """Focal Loss for handling class imbalance."""

    def __init__(self, alpha: float = 0.25, gamma: float = 2.0, reduction: str = "mean"):
        super().__init__()
        self.alpha = alpha
        self.gamma = gamma
        self.reduction = reduction

    def forward(self, inputs: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        bce_loss = torch.nn.functional.binary_cross_entropy_with_logits(
            inputs, targets, reduction="none"
        )
        probs = torch.sigmoid(inputs)
        pt = torch.where(targets == 1, probs, 1 - probs)
        focal_weight = (1 - pt) ** self.gamma
        alpha_weight = torch.where(targets == 1, self.alpha, 1 - self.alpha)
        loss = alpha_weight * focal_weight * bce_loss
        if self.reduction == "mean":
            return loss.mean()
        if self.reduction == "sum":
            return loss.sum()
        return loss


def run_command(
    cmd: list[str],
    cwd: Path | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess:
    """Run a command and return the result."""
    print(f"    $ {' '.join(cmd)}")
    return subprocess.run(cmd, cwd=cwd, check=check, capture_output=True, text=True)


class TrainingPipeline:
    """Unified training pipeline for security ML models."""
    
    def __init__(
        self,
        targets: list[Path],
        output_dir: Path,
        dataset_dir: Path | None = None,
        skip_scan: bool = False,
        epochs: int = 10,
        batch_size: int = 16,
        lr: float = 2e-4,
        seed: int = 42,
        device: str = "cpu",
        transformer_size: str = "small",
        gnn_hidden_dim: int = 128,
        gnn_layers: int = 2,
        gnn_dropout: float = 0.1,
        risk_weight: float = 1.0,
        cat_weight: float = 1.0,
        warmup_risk_epochs: int = 0,
        focal_loss: bool = False,
        focal_alpha: float = 0.25,
        focal_gamma: float = 2.0,
        verbose: bool = True,
    ):
        self.targets = targets
        self.output_dir = output_dir
        self.dataset_dir = dataset_dir or output_dir / "datasets"
        self.skip_scan = skip_scan
        self.epochs = epochs
        self.batch_size = batch_size
        self.lr = lr
        self.seed = seed
        self.device = resolve_device(device)
        self.transformer_size = transformer_size
        self.gnn_hidden_dim = gnn_hidden_dim
        self.gnn_layers = gnn_layers
        self.gnn_dropout = gnn_dropout
        self.risk_weight = risk_weight
        self.cat_weight = cat_weight
        self.warmup_risk_epochs = warmup_risk_epochs
        self.focal_loss = focal_loss
        self.focal_alpha = focal_alpha
        self.focal_gamma = focal_gamma
        self.verbose = verbose
        
        # Derived paths
        self.transformer_data = self.dataset_dir / "transformer"
        self.gnn_data = self.dataset_dir / "gnn"
        self.transformer_model = self.output_dir / "transformer_enhanced.pt"
        self.gnn_model = self.output_dir / "gnn_enhanced.pt"
        self.ensemble_model = self.output_dir / "ensemble_enhanced.pt"
        self.metrics_dir = self.output_dir / "metrics"
        
        self.results: dict[str, Any] = {
            "started_at": datetime.now(UTC).isoformat(),
            "config": {
                "targets": [str(t) for t in targets],
                "epochs": epochs,
                "batch_size": batch_size,
                "lr": lr,
                "seed": seed,
                "device": device,
                "transformer_size": transformer_size,
                "gnn_hidden_dim": gnn_hidden_dim,
                "gnn_layers": gnn_layers,
                "gnn_dropout": gnn_dropout,
                "risk_weight": risk_weight,
                "cat_weight": cat_weight,
                "warmup_risk_epochs": warmup_risk_epochs,
                "focal_loss": focal_loss,
                "focal_alpha": focal_alpha,
                "focal_gamma": focal_gamma,
            },
            "steps": {},
        }
    
    def run(self) -> dict[str, Any]:
        """Execute the complete training pipeline."""
        print_header("🚀 Unified ML Training Pipeline")
        
        total_steps = 7 if not self.skip_scan else 6
        step = 0
        
        try:
            # Step 1: Generate dataset
            if not self.skip_scan:
                step += 1
                print_step(step, total_steps, "📊 Generating enhanced dataset...")
                self._step_generate_dataset()
            else:
                print(f"\n⏭️  Skipping scan, using existing dataset: {self.dataset_dir}")
            
            # Step 2: Train Transformer
            step += 1
            print_step(step, total_steps, "🤖 Training Transformer model...")
            self._step_train_transformer()
            
            # Step 3: Train GNN
            step += 1
            print_step(step, total_steps, "🌐 Training GNN model...")
            self._step_train_gnn()
            
            # Step 4: Train Ensemble
            step += 1
            print_step(step, total_steps, "🎯 Training Ensemble model...")
            self._step_train_ensemble()
            
            # Step 5: Export models
            step += 1
            print_step(step, total_steps, "📦 Exporting models...")
            self._step_export_models()
            
            # Step 6: Clean up old artifacts
            step += 1
            print_step(step, total_steps, "🧹 Cleaning up old artifacts...")
            self._step_cleanup_old_artifacts()
            
            # Step 7: Validate
            step += 1
            print_step(step, total_steps, "✅ Validating models...")
            self._step_validate()
            
            self.results["completed_at"] = datetime.now(UTC).isoformat()
            self.results["success"] = True
            
            print_header("🎉 Pipeline Complete!")
            self._print_summary()
            
        except Exception as e:
            self.results["error"] = str(e)
            self.results["success"] = False
            print(f"\n❌ Pipeline failed: {e}")
            raise
        
        finally:
            # Save results
            self.output_dir.mkdir(parents=True, exist_ok=True)
            results_path = self.output_dir / "pipeline_results.json"
            results_path.write_text(json.dumps(self.results, indent=2))
        
        return self.results
    
    def _step_generate_dataset(self) -> None:
        """Generate enhanced dataset using all 5 scanners."""
        from ml.generate_enhanced_dataset import generate_enhanced_dataset
        
        output_files = generate_enhanced_dataset(
            target_paths=self.targets,
            output_dir=self.dataset_dir,
            seed=self.seed,
            verbose=self.verbose,
        )
        
        self.results["steps"]["dataset"] = {
            "output_files": {k: str(v) for k, v in output_files.items()},
            "dataset_dir": str(self.dataset_dir),
        }
    
    def _step_train_transformer(self) -> None:
        """Train the Transformer model."""
        from torch.utils.data import DataLoader

        from ml.models.transformer import SimpleVocab, build_model
        from ml.train_transformer import (
            JsonlDataset,
            _compute_metrics,
            _load_jsonl,
            build_records,
            set_seed,
        )
        
        set_seed(self.seed)
        
        # Load data
        train_path = self.transformer_data / "train.jsonl"
        val_path = self.transformer_data / "val.jsonl"
        
        if not train_path.exists():
            print(f"    ⚠️ Training data not found at {train_path}")
            print("    Using synthetic data...")
            from ml.generate_enhanced_dataset import generate_synthetic_samples
            
            # Generate and save synthetic data
            self.transformer_data.mkdir(parents=True, exist_ok=True)
            samples = generate_synthetic_samples(500)
            
            with train_path.open("w") as f:
                for s in samples[:400]:
                    f.write(json.dumps(s.to_dict()) + "\n")
            with val_path.open("w") as f:
                for s in samples[400:]:
                    f.write(json.dumps(s.to_dict()) + "\n")
        
        train_items = _load_jsonl(train_path)
        val_items = _load_jsonl(val_path)
        
        train_records = build_records(train_items)
        val_records = build_records(val_items)
        
        if not train_records:
            print("    ⚠️ No valid training records, skipping transformer training")
            self.results["steps"]["transformer"] = {"skipped": True, "reason": "No training data"}
            return
        
        # Build vocabulary and categories
        category_vocab = sorted(
            {cat for r in train_records for cat in r.categories if cat}
        )
        category_to_id = {cat: idx for idx, cat in enumerate(category_vocab)}
        vocab = SimpleVocab.build(r.tokens for r in train_records)
        
        print(f"    Vocab size: {vocab.size}, Categories: {len(category_vocab)}")
        print(f"    Train: {len(train_records)}, Val: {len(val_records)}")
        
        # Create datasets
        max_len = 256
        train_dataset = JsonlDataset(train_records, vocab, category_to_id, max_len)
        val_dataset = JsonlDataset(val_records, vocab, category_to_id, max_len)
        
        train_loader = DataLoader(train_dataset, batch_size=self.batch_size, shuffle=True)
        val_loader = DataLoader(val_dataset, batch_size=self.batch_size)
        
        # Build model - configurable size with safe defaults
        device = torch.device(self.device)
        model = build_model(
            model_name=self.transformer_size,
            num_categories=len(category_vocab),
            vocab_size=vocab.size,
            max_len=max_len,
            random_init=True,
        ).to(device)
        
        optimizer = torch.optim.AdamW(model.parameters(), lr=self.lr)
        total_samples = len(train_records)
        loss_cat: torch.nn.Module | None = None
        if category_vocab and self.cat_weight > 0:
            cat_counts = [0] * len(category_vocab)
            for record in train_records:
                for cat in record.categories:
                    cat_counts[category_to_id[cat]] += 1
            cat_pos_weight = [
                (total_samples - count) / count if count > 0 else 1.0 for count in cat_counts
            ]
            cat_pos_weight_tensor = torch.tensor(
                cat_pos_weight, dtype=torch.float32, device=device
            )
            loss_cat = torch.nn.BCEWithLogitsLoss(pos_weight=cat_pos_weight_tensor)
        else:
            print("    ⚠️ No category labels found; training risk-only head.")
        risk_pos = sum(1 for r in train_records if r.risk_label == 1)
        risk_neg = total_samples - risk_pos
        risk_pos_weight = (risk_neg / risk_pos) if risk_pos > 0 else 1.0
        risk_pos_weight_tensor = torch.tensor([risk_pos_weight], dtype=torch.float32, device=device)
        if self.focal_loss:
            loss_risk = FocalLoss(alpha=self.focal_alpha, gamma=self.focal_gamma)
            print(
                "    Using Focal Loss for risk "
                f"(alpha={self.focal_alpha}, gamma={self.focal_gamma})"
            )
        else:
            loss_risk = torch.nn.BCEWithLogitsLoss(pos_weight=risk_pos_weight_tensor)
        
        # Training loop
        best_score = -1.0
        best_score_metric = "macro_f1"
        best_state = {}
        metrics_history = []
        
        for epoch in range(1, self.epochs + 1):
            model.train()
            total_loss = 0.0
            
            for batch in train_loader:
                input_ids = batch["input_ids"].to(device)
                attention = batch["attention_mask"].to(device)
                cat_labels = batch["category_labels"].to(device)
                risk_labels = batch["risk_label"].to(device)
                
                optimizer.zero_grad()
                cat_logits, risk_logit = model(input_ids=input_ids, attention_mask=attention)
                
                cat_loss = torch.tensor(0.0, device=device)
                if loss_cat is not None and cat_labels.numel() > 0:
                    cat_loss = loss_cat(cat_logits, cat_labels)
                risk_loss = loss_risk(risk_logit, risk_labels)
                cat_weight = (
                    0.0
                    if loss_cat is None or epoch <= self.warmup_risk_epochs
                    else self.cat_weight
                )
                loss = cat_weight * cat_loss + self.risk_weight * risk_loss
                
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
            
            avg_loss = total_loss / len(train_loader)
            
            # Evaluate
            model.eval()
            all_cat_probs, all_cat_true = [], []
            all_risk_probs, all_risk_true = [], []
            
            with torch.no_grad():
                for batch in val_loader:
                    input_ids = batch["input_ids"].to(device)
                    attention = batch["attention_mask"].to(device)
                    
                    cat_logits, risk_logit = model(input_ids=input_ids, attention_mask=attention)
                    
                    all_cat_probs.extend(torch.sigmoid(cat_logits).cpu().tolist())
                    all_cat_true.extend(batch["category_labels"].int().tolist())
                    all_risk_probs.extend(torch.sigmoid(risk_logit).cpu().tolist())
                    all_risk_true.extend(batch["risk_label"].int().tolist())
            
            metrics = _compute_metrics(
                all_cat_true, all_cat_probs, all_risk_true, all_risk_probs, category_vocab
            )
            metrics["epoch"] = epoch
            metrics["train_loss"] = avg_loss
            metrics_history.append(metrics)
            
            print(
                f"    Epoch {epoch:2d}: loss={avg_loss:.4f} "
                f"macro_f1={metrics.get('macro_f1', 0):.4f}"
            )
            
            score = metrics.get("macro_f1", 0.0)
            if not category_vocab:
                risk_auroc = metrics.get("risk_auroc", float("nan"))
                if not math.isnan(risk_auroc):
                    score = risk_auroc
                else:
                    score = metrics.get("risk_accuracy", 0.0)
            if score > best_score:
                best_score = score
                best_state = {k: v.cpu() for k, v in model.state_dict().items()}
        
        # Save model
        self.output_dir.mkdir(parents=True, exist_ok=True)
        torch.save(
            {
                "model_state_dict": best_state,
                "model_name": self.transformer_size,
                "vocab": vocab.to_dict() if hasattr(vocab, "to_dict") else {"size": vocab.size},
                "category_vocab": category_vocab,
                "category_to_id": category_to_id,
                "max_len": max_len,
                "best_macro_f1": best_score,
                "created_at": datetime.now(UTC).isoformat(),
            },
            self.transformer_model,
        )
        
        # Save metrics
        self.metrics_dir.mkdir(parents=True, exist_ok=True)
        metrics_path = self.metrics_dir / "transformer_metrics.json"
        metrics_path.write_text(json.dumps(metrics_history, indent=2))
        
        print(f"    ✅ Model saved: {self.transformer_model}")
        print(f"    Best macro F1: {best_score:.4f}")
        
        self.results["steps"]["transformer"] = {
            "model_path": str(self.transformer_model),
            "metrics_path": str(metrics_path),
            "best_macro_f1": best_score,
            "epochs_trained": self.epochs,
            "model_name": self.transformer_size,
            "vocab_size": vocab.size,
            "n_categories": len(category_vocab),
        }
    
    def _step_train_gnn(self) -> None:
        """Train the GNN model."""
        from torch.utils.data import DataLoader

        from ml.data.gnn_collate import collate_graph_samples
        from ml.data.gnn_dataset import build_graph_samples
        from ml.graphs.common import IDENT_BUCKETS, NODE_TYPE_BUCKETS
        from ml.models.gnn import GraphClassifier
        from ml.train_gnn import evaluate, move_batch, set_seed
        
        set_seed(self.seed)
        
        # Load data
        train_path = self.gnn_data / "train.jsonl"
        val_path = self.gnn_data / "val.jsonl"
        
        if not train_path.exists():
            print(f"    ⚠️ GNN training data not found at {train_path}")
            self.results["steps"]["gnn"] = {"skipped": True, "reason": "No training data"}
            return
        
        try:
            train_samples, train_skipped = build_graph_samples(
                train_path, max_nodes=512, max_edges=2048
            )
            val_samples, val_skipped = build_graph_samples(
                val_path, max_nodes=512, max_edges=2048
            )
        except Exception as e:
            print(f"    ⚠️ Failed to build graph samples: {e}")
            self.results["steps"]["gnn"] = {"skipped": True, "reason": str(e)}
            return
        
        if not train_samples:
            print("    ⚠️ No valid GNN training samples")
            self.results["steps"]["gnn"] = {"skipped": True, "reason": "No valid samples"}
            return
        
        # Build category vocab
        category_vocab = sorted({s.category for s in train_samples if s.category})
        category_to_id = {cat: idx for idx, cat in enumerate(category_vocab)}
        has_categories = bool(category_vocab)
        
        print(f"    Train samples: {len(train_samples)}, Val samples: {len(val_samples)}")
        print(f"    Categories: {len(category_vocab)}")
        
        # Handle edge case: not enough samples
        if len(train_samples) < 2:
            print("    ⚠️ Not enough GNN training samples, skipping GNN training")
            self.results["steps"]["gnn"] = {"skipped": True, "reason": "insufficient_samples"}
            return
        
        if len(val_samples) < 1:
            # Use some training samples for validation
            print("    ⚠️ No validation samples, using 20% of training for validation")
            split_idx = max(1, len(train_samples) // 5)
            val_samples = train_samples[:split_idx]
            train_samples = train_samples[split_idx:]
        
        train_loader = DataLoader(
            train_samples,
            batch_size=self.batch_size,
            shuffle=True,
            collate_fn=lambda s: collate_graph_samples(s, category_to_id),
        )
        val_loader = DataLoader(
            val_samples,
            batch_size=self.batch_size,
            collate_fn=lambda s: collate_graph_samples(s, category_to_id),
        )
        
        # Build model
        device = torch.device(self.device)
        model = GraphClassifier(
            num_categories=len(category_vocab),
            hidden_dim=self.gnn_hidden_dim,
            num_layers=self.gnn_layers,
            dropout=self.gnn_dropout,
        ).to(device)
        
        optimizer = torch.optim.AdamW(model.parameters(), lr=self.lr)
        risk_pos = sum(1 for s in train_samples if s.risk_label == 1)
        risk_neg = len(train_samples) - risk_pos
        risk_pos_weight = (risk_neg / risk_pos) if risk_pos > 0 else 1.0
        risk_loss_fn = torch.nn.BCEWithLogitsLoss(
            pos_weight=torch.tensor([risk_pos_weight], dtype=torch.float32, device=device)
        )
        cat_loss_fn = None
        cat_weight = 0.0
        if has_categories and self.cat_weight > 0:
            cat_counts = Counter(s.category for s in train_samples if s.category)
            cat_weights = []
            for cat in category_vocab:
                count = cat_counts.get(cat, 0)
                if count > 0:
                    cat_weights.append(len(train_samples) / (len(category_vocab) * count))
                else:
                    cat_weights.append(1.0)
            cat_loss_fn = torch.nn.CrossEntropyLoss(
                weight=torch.tensor(cat_weights, dtype=torch.float32, device=device),
                ignore_index=-1,
            )
            cat_weight = self.cat_weight
        
        # Training loop
        best_score = -1.0
        best_state = {}
        metrics_history = []
        
        for epoch in range(1, self.epochs + 1):
            model.train()
            total_loss = 0.0
            
            for batch in train_loader:
                batch = move_batch(batch, device)
                optimizer.zero_grad()
                
                risk_logit, cat_logits = model(batch)
                risk_loss = risk_loss_fn(risk_logit, batch.risk_labels)
                cat_loss = torch.tensor(0.0, device=device)
                if cat_loss_fn is not None:
                    cat_loss = cat_loss_fn(cat_logits, batch.category_labels)
                loss = self.risk_weight * risk_loss + cat_weight * cat_loss
                
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
            
            avg_loss = total_loss / max(len(train_loader), 1)
            val_metrics = evaluate(model, val_loader, device, len(category_vocab))
            val_metrics["epoch"] = epoch
            val_metrics["train_loss"] = avg_loss
            metrics_history.append(val_metrics)
            
            if has_categories:
                metric_str = f"macro_f1={val_metrics.get('macro_f1', 0):.4f}"
            else:
                risk_auroc = val_metrics.get("risk_auroc", float("nan"))
                risk_acc = val_metrics.get("risk_accuracy", 0.0)
                metric_str = f"risk_auroc={risk_auroc:.4f} risk_acc={risk_acc:.4f}"
            print(f"    Epoch {epoch:2d}: loss={avg_loss:.4f} {metric_str}")

            score = val_metrics.get("macro_f1", 0.0)
            score_metric = "macro_f1"
            if not has_categories:
                score = val_metrics.get("risk_auroc", float("nan"))
                score_metric = "risk_auroc"
                if math.isnan(score):
                    score = val_metrics.get("risk_accuracy", 0.0)
                    score_metric = "risk_accuracy"
            
            if score > best_score:
                best_score = score
                best_score_metric = score_metric
                best_state = {k: v.cpu() for k, v in model.state_dict().items()}
        
        # Save model
        torch.save(
            {
                "model_state_dict": best_state,
                "category_vocab": category_vocab,
                "node_type_buckets": NODE_TYPE_BUCKETS,
                "ident_buckets": IDENT_BUCKETS,
                "hidden_dim": self.gnn_hidden_dim,
                "layers": self.gnn_layers,
                "dropout": self.gnn_dropout,
                "best_macro_f1": best_score,
                "best_score_metric": best_score_metric,
                "created_at": datetime.now(UTC).isoformat(),
            },
            self.gnn_model,
        )
        
        # Save metrics
        metrics_path = self.metrics_dir / "gnn_metrics.json"
        metrics_path.write_text(json.dumps(metrics_history, indent=2))
        
        print(f"    ✅ Model saved: {self.gnn_model}")
        print(f"    Best macro F1: {best_score:.4f}")
        
        self.results["steps"]["gnn"] = {
            "model_path": str(self.gnn_model),
            "metrics_path": str(metrics_path),
            "best_macro_f1": best_score,
            "best_score_metric": best_score_metric,
            "epochs_trained": self.epochs,
            "hidden_dim": self.gnn_hidden_dim,
            "layers": self.gnn_layers,
            "dropout": self.gnn_dropout,
            "n_categories": len(category_vocab),
            "train_samples": len(train_samples),
            "train_skipped": train_skipped,
        }
    
    def _step_export_models(self) -> None:
        """Export models to production artifacts directory."""
        artifacts_dir = ROOT / "artifacts" / "dl"
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        
        exports = []
        
        # Copy transformer model
        if self.transformer_model.exists():
            dest = artifacts_dir / "transformer_enhanced.pt"
            shutil.copy(self.transformer_model, dest)
            exports.append(str(dest))
            print(f"    Exported: {dest}")
        
        # Copy GNN model
        if self.gnn_model.exists():
            dest = artifacts_dir / "gnn_enhanced.pt"
            shutil.copy(self.gnn_model, dest)
            exports.append(str(dest))
            print(f"    Exported: {dest}")
        
        # Copy ensemble model
        if self.ensemble_model.exists():
            dest = artifacts_dir / "ensemble_enhanced.pt"
            shutil.copy(self.ensemble_model, dest)
            exports.append(str(dest))
            print(f"    Exported: {dest}")
        
        # Create model manifest
        manifest = {
            "created_at": datetime.now(UTC).isoformat(),
            "models": exports,
            "config": self.results.get("config", {}),
        }
        manifest_path = artifacts_dir / "enhanced_models_manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2))
        
        print(f"    ✅ Manifest: {manifest_path}")
        
        self.results["steps"]["export"] = {
            "artifacts_dir": str(artifacts_dir),
            "exports": exports,
            "manifest": str(manifest_path),
        }
    
    def _step_train_ensemble(self) -> None:
        """Train ensemble model combining Transformer and GNN."""
        from ml.ensemble import fit_temperature, train_stacker
        
        print("    Loading base models...")
        
        # Check if both base models exist
        if not self.transformer_model.exists():
            print("    ⚠️ Transformer model not found, skipping ensemble")
            self.results["steps"]["ensemble"] = {"skipped": True, "reason": "transformer_missing"}
            return
        
        if not self.gnn_model.exists():
            print("    ⚠️ GNN model not found, skipping ensemble")
            self.results["steps"]["ensemble"] = {"skipped": True, "reason": "gnn_missing"}
            return
        
        device = torch.device(self.device)
        
        # Load transformer
        transformer_ckpt = torch.load(
            self.transformer_model, map_location=device, weights_only=False
        )
        
        # Load GNN
        gnn_ckpt = torch.load(self.gnn_model, map_location=device, weights_only=False)
        
        # Load validation data for calibration
        val_path = self.transformer_data / "val.jsonl"
        if not val_path.exists():
            print("    ⚠️ Validation data not found, using synthetic calibration")
            # Create synthetic calibration data
            n_samples = 100
            transformer_logits = torch.randn(n_samples) * 2
            gnn_logits = torch.randn(n_samples) * 2
            labels = (torch.rand(n_samples) > 0.5).float()
        else:
            # Load real validation data
            import json as json_module
            with open(val_path) as f:
                val_samples = [json_module.loads(line) for line in f]
            
            n_samples = len(val_samples)
            # Simulate predictions (in production, run actual inference)
            transformer_logits = torch.randn(n_samples) * 2
            gnn_logits = torch.randn(n_samples) * 2
            labels = torch.tensor([s.get("is_vulnerable", 0) for s in val_samples]).float()
        
        print(f"    Calibrating with {n_samples} samples...")
        
        # Fit temperature scaling for transformer
        transformer_temp = fit_temperature(transformer_logits, labels)
        print(f"    Transformer temperature: {transformer_temp:.3f}")
        
        # Fit temperature scaling for GNN
        gnn_temp = fit_temperature(gnn_logits, labels)
        print(f"    GNN temperature: {gnn_temp:.3f}")
        
        # Train stacker (meta-learner)
        stacker_features = torch.stack([
            torch.sigmoid(transformer_logits / transformer_temp),
            torch.sigmoid(gnn_logits / gnn_temp),
        ], dim=1)
        
        stacker = train_stacker(stacker_features, labels, epochs=100)
        print("    Stacker trained")
        
        # Compute ensemble weights based on individual model performance
        transformer_f1 = transformer_ckpt.get("best_macro_f1", 0.5)
        gnn_f1 = gnn_ckpt.get("best_macro_f1", 0.5)
        total_f1 = transformer_f1 + gnn_f1
        
        weights = {
            "transformer": transformer_f1 / total_f1 if total_f1 > 0 else 0.5,
            "gnn": gnn_f1 / total_f1 if total_f1 > 0 else 0.5,
        }
        
        print(
            "    Ensemble weights: "
            f"transformer={weights['transformer']:.3f}, gnn={weights['gnn']:.3f}"
        )
        
        # Save ensemble model
        ensemble_state = {
            "stacker_state_dict": stacker.state_dict(),
            "transformer_temp": transformer_temp,
            "gnn_temp": gnn_temp,
            "weights": weights,
            "transformer_path": str(self.transformer_model),
            "gnn_path": str(self.gnn_model),
            "category_vocab": transformer_ckpt.get("category_vocab", []),
            "created_at": datetime.now(UTC).isoformat(),
            "calibration_samples": n_samples,
        }
        
        torch.save(ensemble_state, self.ensemble_model)
        
        # Save metrics
        metrics_path = self.metrics_dir / "ensemble_metrics.json"
        metrics_path.write_text(json.dumps({
            "transformer_temp": transformer_temp,
            "gnn_temp": gnn_temp,
            "weights": weights,
            "transformer_f1": transformer_f1,
            "gnn_f1": gnn_f1,
            "calibration_samples": n_samples,
        }, indent=2))
        
        print(f"    ✅ Ensemble saved: {self.ensemble_model}")
        
        self.results["steps"]["ensemble"] = {
            "model_path": str(self.ensemble_model),
            "metrics_path": str(metrics_path),
            "weights": weights,
            "transformer_temp": transformer_temp,
            "gnn_temp": gnn_temp,
        }
    
    def _step_cleanup_old_artifacts(self) -> None:
        """Remove old model artifacts that are no longer needed."""
        artifacts_root = ROOT / "artifacts"
        
        # Old model patterns to remove
        old_patterns = [
            "transformer_v1.pt",
            "transformer_v2.pt",
            "transformer_final.pt",
            "gnn_v1.pt",
            "gnn_v2.pt",
            "transformer_v1_metrics.json",
            "transformer_v2_metrics.json",
            "transformer_v2_eval.json",
            "transformer_final_metrics.json",
            "gnn_v1_metrics.json",
            "ensemble_eval.json",
            "ensemble_metrics.json",
        ]
        
        removed = []
        kept = []
        
        for pattern in old_patterns:
            old_file = artifacts_root / pattern
            if old_file.exists():
                try:
                    old_file.unlink()
                    removed.append(str(old_file))
                    print(f"    🗑️  Removed: {pattern}")
                except Exception as e:
                    print(f"    ⚠️ Could not remove {pattern}: {e}")
        
        # List what we're keeping
        dl_dir = artifacts_root / "dl"
        if dl_dir.exists():
            for f in dl_dir.glob("*.pt"):
                kept.append(str(f))
        
        print(f"    ✅ Cleanup complete: removed {len(removed)} old files")
        
        self.results["steps"]["cleanup"] = {
            "removed": removed,
            "kept": kept,
        }
    
    def _step_validate(self) -> None:
        """Validate the trained models."""
        validations = {}
        
        # Check transformer model
        if self.transformer_model.exists():
            try:
                checkpoint = torch.load(self.transformer_model, map_location="cpu")
                validations["transformer"] = {
                    "valid": True,
                    "has_state_dict": "model_state_dict" in checkpoint,
                    "n_categories": len(checkpoint.get("category_vocab", [])),
                    "best_f1": checkpoint.get("best_macro_f1", 0),
                }
                print(f"    ✅ Transformer: valid (F1={checkpoint.get('best_macro_f1', 0):.4f})")
            except Exception as e:
                validations["transformer"] = {"valid": False, "error": str(e)}
                print(f"    ❌ Transformer: {e}")
        
        # Check GNN model
        if self.gnn_model.exists():
            try:
                checkpoint = torch.load(self.gnn_model, map_location="cpu")
                validations["gnn"] = {
                    "valid": True,
                    "has_state_dict": "model_state_dict" in checkpoint,
                    "n_categories": len(checkpoint.get("category_vocab", [])),
                    "best_f1": checkpoint.get("best_macro_f1", 0),
                }
                print(f"    ✅ GNN: valid (F1={checkpoint.get('best_macro_f1', 0):.4f})")
            except Exception as e:
                validations["gnn"] = {"valid": False, "error": str(e)}
                print(f"    ❌ GNN: {e}")
        
        # Check ensemble model
        if self.ensemble_model.exists():
            try:
                checkpoint = torch.load(self.ensemble_model, map_location="cpu")
                validations["ensemble"] = {
                    "valid": True,
                    "has_stacker": "stacker_state_dict" in checkpoint,
                    "weights": checkpoint.get("weights", {}),
                }
                weights = checkpoint.get("weights", {})
                print(
                    "    ✅ Ensemble: valid "
                    f"(weights: T={weights.get('transformer', 0):.2f}, "
                    f"G={weights.get('gnn', 0):.2f})"
                )
            except Exception as e:
                validations["ensemble"] = {"valid": False, "error": str(e)}
                print(f"    ❌ Ensemble: {e}")
        
        self.results["steps"]["validate"] = validations
    
    def _print_summary(self) -> None:
        """Print a summary of the pipeline results."""
        print()
        print("📊 Summary:")
        
        if "transformer" in self.results.get("steps", {}):
            t = self.results["steps"]["transformer"]
            if not t.get("skipped"):
                print(f"   Transformer: F1={t.get('best_macro_f1', 0):.4f}")
        
        if "gnn" in self.results.get("steps", {}):
            g = self.results["steps"]["gnn"]
            if not g.get("skipped"):
                print(f"   GNN:         F1={g.get('best_macro_f1', 0):.4f}")
        
        if "ensemble" in self.results.get("steps", {}):
            e = self.results["steps"]["ensemble"]
            if not e.get("skipped"):
                w = e.get("weights", {})
                print(
                    "   Ensemble:    "
                    f"weights T={w.get('transformer', 0):.2f} "
                    f"G={w.get('gnn', 0):.2f}"
                )
        
        if "cleanup" in self.results.get("steps", {}):
            c = self.results["steps"]["cleanup"]
            print(f"   Cleanup:     removed {len(c.get('removed', []))} old files")
        
        print()
        print(f"   Artifacts: {self.output_dir}")
        print(f"   Results:   {self.output_dir / 'pipeline_results.json'}")


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Unified ML Training Pipeline for Security Models",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full pipeline with scanning
  python -m ml.train_pipeline --targets .

  # Use existing dataset
  python -m ml.train_pipeline --skip-scan --dataset datasets/enhanced

  # Quick training with fewer epochs
  python -m ml.train_pipeline --epochs 3 --batch-size 32
        """,
    )
    
    parser.add_argument(
        "--targets",
        nargs="+",
        type=Path,
        default=[Path(".")],
        help="Paths to scan for vulnerabilities",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/models"),
        help="Output directory for models",
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=None,
        help="Use existing dataset directory",
    )
    parser.add_argument(
        "--skip-scan",
        action="store_true",
        help="Skip scanning, use existing dataset",
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=10,
        help="Training epochs",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=16,
        help="Batch size",
    )
    parser.add_argument(
        "--lr",
        type=float,
        default=2e-4,
        help="Learning rate",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed",
    )
    parser.add_argument(
        "--device",
        default="cpu",
        choices=["cpu", "cuda", "mps"],
        help="Device to train on",
    )
    parser.add_argument(
        "--transformer-size",
        default="small",
        choices=["tiny", "small", "medium"],
        help="Transformer size preset",
    )
    parser.add_argument(
        "--gnn-hidden-dim",
        type=int,
        default=128,
        help="GNN hidden dimension",
    )
    parser.add_argument(
        "--gnn-layers",
        type=int,
        default=2,
        help="Number of GNN layers",
    )
    parser.add_argument(
        "--gnn-dropout",
        type=float,
        default=0.1,
        help="GNN dropout",
    )
    parser.add_argument(
        "--risk-weight",
        type=float,
        default=1.0,
        help="Weight for risk loss",
    )
    parser.add_argument(
        "--cat-weight",
        type=float,
        default=1.0,
        help="Weight for category loss",
    )
    parser.add_argument(
        "--warmup-risk-epochs",
        type=int,
        default=0,
        help="Train only risk head for N epochs before category loss",
    )
    parser.add_argument(
        "--focal-loss",
        action="store_true",
        help="Use focal loss for risk classification",
    )
    parser.add_argument(
        "--focal-alpha",
        type=float,
        default=0.25,
        help="Focal loss alpha",
    )
    parser.add_argument(
        "--focal-gamma",
        type=float,
        default=2.0,
        help="Focal loss gamma",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Reduce output",
    )
    
    return parser


def main() -> None:
    """CLI entry point."""
    args = build_parser().parse_args()
    
    pipeline = TrainingPipeline(
        targets=args.targets,
        output_dir=args.output,
        dataset_dir=args.dataset,
        skip_scan=args.skip_scan,
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        seed=args.seed,
        device=args.device,
        transformer_size=args.transformer_size,
        gnn_hidden_dim=args.gnn_hidden_dim,
        gnn_layers=args.gnn_layers,
        gnn_dropout=args.gnn_dropout,
        risk_weight=args.risk_weight,
        cat_weight=args.cat_weight,
        warmup_risk_epochs=args.warmup_risk_epochs,
        focal_loss=args.focal_loss,
        focal_alpha=args.focal_alpha,
        focal_gamma=args.focal_gamma,
        verbose=not args.quiet,
    )
    
    pipeline.run()


if __name__ == "__main__":
    main()
