#!/usr/bin/env python3
"""
Binary-focused training for vulnerability detection.

This module trains a simpler, more focused model on the binary classification task
(vulnerable vs safe) with proper handling for limited data scenarios.
"""

from __future__ import annotations

import json
import random
from pathlib import Path
from dataclasses import dataclass
from typing import Any

import numpy as np
import torch
from torch import nn
from torch.utils.data import DataLoader, Dataset


def set_seed(seed: int = 42) -> None:
    """Set random seeds for reproducibility."""
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


@dataclass
class BinaryRecord:
    """A single training record for binary classification."""

    tokens: list[str]
    is_vulnerable: int  # 0 or 1
    code_snippet: str


class SimpleVocab:
    """Simplified vocabulary for the binary classifier."""

    PAD = "[PAD]"
    UNK = "[UNK]"
    CLS = "[CLS]"
    SEP = "[SEP]"

    def __init__(self, token_to_id: dict[str, int]):
        self.token_to_id = token_to_id
        self.id_to_token = {v: k for k, v in token_to_id.items()}
        self.pad_id = token_to_id.get(self.PAD, 0)
        self.unk_id = token_to_id.get(self.UNK, 1)
        self.cls_id = token_to_id.get(self.CLS, 2)
        self.sep_id = token_to_id.get(self.SEP, 3)

    @classmethod
    def build(
        cls, token_lists: list[list[str]], min_freq: int = 2, max_vocab: int = 5000
    ) -> "SimpleVocab":
        """Build vocabulary from token lists."""
        from collections import Counter

        counts: Counter[str] = Counter()
        for tokens in token_lists:
            counts.update(tokens)

        # Start with special tokens
        token_to_id = {
            cls.PAD: 0,
            cls.UNK: 1,
            cls.CLS: 2,
            cls.SEP: 3,
        }

        # Add frequent tokens
        for token, freq in counts.most_common(max_vocab - 4):
            if freq >= min_freq and token not in token_to_id:
                token_to_id[token] = len(token_to_id)

        return cls(token_to_id)

    def encode(self, tokens: list[str], max_len: int) -> tuple[list[int], list[int]]:
        """Encode tokens to IDs with attention mask."""
        ids = [self.cls_id]
        for t in tokens[: max_len - 2]:
            ids.append(self.token_to_id.get(t, self.unk_id))
        ids.append(self.sep_id)

        attention = [1] * len(ids)
        padding = max_len - len(ids)
        if padding > 0:
            ids.extend([self.pad_id] * padding)
            attention.extend([0] * padding)

        return ids, attention

    @property
    def size(self) -> int:
        return len(self.token_to_id)

    def to_dict(self) -> dict:
        return {"token_to_id": self.token_to_id}

    @classmethod
    def from_dict(cls, data: dict) -> "SimpleVocab":
        return cls(data["token_to_id"])


class BinaryClassifier(nn.Module):
    """Simple but effective binary classifier for vulnerability detection."""

    def __init__(
        self,
        vocab_size: int,
        embed_dim: int = 128,
        hidden_dim: int = 256,
        num_layers: int = 2,
        dropout: float = 0.3,
    ):
        super().__init__()

        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)

        # Bidirectional LSTM for better context understanding
        self.lstm = nn.LSTM(
            embed_dim,
            hidden_dim // 2,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if num_layers > 1 else 0,
        )

        self.attention = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 4),
            nn.Tanh(),
            nn.Linear(hidden_dim // 4, 1),
        )

        self.classifier = nn.Sequential(
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, 1),
        )

        # Initialize weights
        self._init_weights()

    def _init_weights(self):
        """Initialize weights properly to avoid collapse."""
        for name, param in self.named_parameters():
            if "weight" in name and param.dim() > 1:
                nn.init.xavier_uniform_(param)
            elif "bias" in name:
                nn.init.zeros_(param)

        # Special init for classifier to encourage varied outputs
        nn.init.xavier_normal_(self.classifier[-1].weight, gain=0.5)
        nn.init.zeros_(self.classifier[-1].bias)

    def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        # Embed
        x = self.embedding(input_ids)  # (batch, seq, embed)

        # LSTM
        x, _ = self.lstm(x)  # (batch, seq, hidden)

        # Attention
        attn_weights = self.attention(x)  # (batch, seq, 1)
        attn_weights = attn_weights.squeeze(-1)  # (batch, seq)

        # Mask padding
        attn_weights = attn_weights.masked_fill(attention_mask == 0, float("-inf"))
        attn_weights = torch.softmax(attn_weights, dim=-1)  # (batch, seq)

        # Weighted sum
        x = torch.bmm(attn_weights.unsqueeze(1), x).squeeze(1)  # (batch, hidden)

        # Classify
        logit = self.classifier(x).squeeze(-1)  # (batch,)

        return logit

    def predict(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        """Get probability of being vulnerable."""
        self.eval()
        with torch.no_grad():
            logit = self(input_ids, attention_mask)
            return torch.sigmoid(logit)


class BinaryDataset(Dataset):
    """Dataset for binary vulnerability classification."""

    def __init__(
        self,
        records: list[BinaryRecord],
        vocab: SimpleVocab,
        max_len: int = 256,
    ):
        self.records = records
        self.vocab = vocab
        self.max_len = max_len

    def __len__(self) -> int:
        return len(self.records)

    def __getitem__(self, idx: int) -> dict[str, torch.Tensor]:
        record = self.records[idx]
        ids, attention = self.vocab.encode(record.tokens, self.max_len)

        return {
            "input_ids": torch.tensor(ids, dtype=torch.long),
            "attention_mask": torch.tensor(attention, dtype=torch.long),
            "label": torch.tensor(record.is_vulnerable, dtype=torch.float32),
        }


def load_records(jsonl_path: Path) -> list[BinaryRecord]:
    """Load records from JSONL file."""
    import re

    records = []
    with open(jsonl_path) as f:
        for line in f:
            if not line.strip():
                continue
            item = json.loads(line)

            # Extract label (vulnerable = 1, safe = 0)
            label = None
            if "label" in item:
                label = int(item["label"])
            elif "is_vulnerable" in item:
                label = 1 if item["is_vulnerable"] else 0
            elif "verdict" in item:
                label = 1 if item["verdict"] == "TP" else 0

            if label is None:
                continue

            # Extract tokens
            code = item.get("code_snippet") or item.get("code") or ""
            if not code:
                continue

            # Simple tokenization
            tokens = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*|[0-9]+|[^\s\w]", code)
            if len(tokens) < 5:
                continue

            records.append(
                BinaryRecord(
                    tokens=tokens,
                    is_vulnerable=label,
                    code_snippet=code,
                )
            )

    return records


def train_binary_model(
    train_path: Path,
    val_path: Path,
    output_dir: Path,
    epochs: int = 50,
    batch_size: int = 16,
    lr: float = 0.001,
    seed: int = 42,
    verbose: bool = True,
) -> dict[str, Any]:
    """Train the binary classifier."""
    set_seed(seed)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    if verbose:
        print(f"🔧 Training binary classifier on {device}")

    # Load data
    train_records = load_records(train_path)
    val_records = load_records(val_path)

    if verbose:
        print(f"   📊 Train: {len(train_records)}, Val: {len(val_records)}")
        train_vuln = sum(r.is_vulnerable for r in train_records)
        train_safe = len(train_records) - train_vuln
        print(f"   📊 Train balance: {train_vuln} vuln / {train_safe} safe")

    if not train_records:
        raise ValueError("No training records found")

    # Build vocabulary
    all_tokens = [r.tokens for r in train_records]
    vocab = SimpleVocab.build(all_tokens, min_freq=2, max_vocab=5000)

    if verbose:
        print(f"   📚 Vocabulary size: {vocab.size}")

    # Create datasets
    train_ds = BinaryDataset(train_records, vocab)
    val_ds = BinaryDataset(val_records, vocab) if val_records else train_ds

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=batch_size)

    # Create model
    model = BinaryClassifier(
        vocab_size=vocab.size,
        embed_dim=128,
        hidden_dim=256,
        num_layers=2,
        dropout=0.3,
    ).to(device)

    if verbose:
        params = sum(p.numel() for p in model.parameters())
        print(f"   🧠 Model parameters: {params:,}")

    # Class weights for imbalanced data
    n_vuln = sum(r.is_vulnerable for r in train_records)
    n_safe = len(train_records) - n_vuln
    pos_weight = torch.tensor([n_safe / max(n_vuln, 1)]).to(device)

    # Loss and optimizer
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=0.01)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode="max", factor=0.5, patience=5
    )

    # Training
    best_f1 = 0.0
    best_state = None
    patience_counter = 0
    max_patience = 10

    for epoch in range(epochs):
        # Train
        model.train()
        train_loss = 0.0
        train_preds = []
        train_labels = []

        for batch in train_loader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["label"].to(device)

            optimizer.zero_grad()
            logits = model(input_ids, attention_mask)
            loss = criterion(logits, labels)

            # Add L2 regularization
            l2_reg = 0.0
            for param in model.parameters():
                l2_reg += torch.norm(param, 2)
            loss = loss + 0.001 * l2_reg

            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()

            train_loss += loss.item()
            train_preds.extend((torch.sigmoid(logits) > 0.5).int().cpu().tolist())
            train_labels.extend(labels.int().cpu().tolist())

        train_loss /= len(train_loader)

        # Validate
        model.eval()
        val_preds = []
        val_labels = []
        val_probs = []

        with torch.no_grad():
            for batch in val_loader:
                input_ids = batch["input_ids"].to(device)
                attention_mask = batch["attention_mask"].to(device)
                labels = batch["label"]

                logits = model(input_ids, attention_mask)
                probs = torch.sigmoid(logits).cpu()

                val_probs.extend(probs.tolist())
                val_preds.extend((probs > 0.5).int().tolist())
                val_labels.extend(labels.int().tolist())

        # Compute metrics
        from sklearn.metrics import f1_score, precision_score, recall_score, accuracy_score

        val_f1 = f1_score(val_labels, val_preds, zero_division=0)
        val_precision = precision_score(val_labels, val_preds, zero_division=0)
        val_recall = recall_score(val_labels, val_preds, zero_division=0)
        val_acc = accuracy_score(val_labels, val_preds)

        scheduler.step(val_f1)

        if verbose and (epoch + 1) % 5 == 0:
            print(
                f"   Epoch {epoch+1:3d}: loss={train_loss:.4f}, "
                f"F1={val_f1:.4f}, P={val_precision:.4f}, R={val_recall:.4f}, Acc={val_acc:.4f}"
            )
            # Show prediction distribution
            pred_dist = np.mean(val_preds)
            prob_dist = np.mean(val_probs)
            print(f"             Pred dist: {pred_dist:.2%} positive, Avg prob: {prob_dist:.3f}")

        # Early stopping
        if val_f1 > best_f1:
            best_f1 = val_f1
            best_state = {
                "model": model.state_dict(),
                "vocab": vocab.to_dict(),
                "metrics": {
                    "f1": val_f1,
                    "precision": val_precision,
                    "recall": val_recall,
                    "accuracy": val_acc,
                },
            }
            patience_counter = 0
        else:
            patience_counter += 1
            if patience_counter >= max_patience:
                if verbose:
                    print(f"   Early stopping at epoch {epoch+1}")
                break

    # Save model
    output_dir.mkdir(parents=True, exist_ok=True)
    checkpoint_path = output_dir / "binary_classifier.pt"

    if best_state is None:
        # Use final state if no improvement
        best_state = {
            "model": model.state_dict(),
            "vocab": vocab.to_dict(),
            "metrics": {"f1": 0.0},
        }

    torch.save(best_state, checkpoint_path)

    if verbose:
        print(f"   ✅ Model saved to {checkpoint_path}")
        print(f"   📈 Best F1: {best_f1:.4f}")

    return {
        "checkpoint_path": str(checkpoint_path),
        "best_f1": best_f1,
        "metrics": best_state["metrics"],
        "vocab_size": vocab.size,
    }


def load_binary_model(
    checkpoint_path: Path, device: str = "cpu"
) -> tuple[BinaryClassifier, SimpleVocab]:
    """Load a trained binary classifier."""
    checkpoint = torch.load(checkpoint_path, map_location=device)

    vocab = SimpleVocab.from_dict(checkpoint["vocab"])
    model = BinaryClassifier(vocab_size=vocab.size)
    model.load_state_dict(checkpoint["model"])
    model.to(device)
    model.eval()

    return model, vocab


def predict_vulnerability(
    code: str,
    model: BinaryClassifier,
    vocab: SimpleVocab,
    max_len: int = 256,
) -> float:
    """Predict vulnerability probability for a code snippet."""
    import re

    tokens = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*|[0-9]+|[^\s\w]", code)
    ids, attention = vocab.encode(tokens, max_len)

    input_ids = torch.tensor([ids], dtype=torch.long)
    attention_mask = torch.tensor([attention], dtype=torch.long)

    with torch.no_grad():
        prob = model.predict(input_ids, attention_mask)

    return prob.item()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Train binary vulnerability classifier")
    parser.add_argument("--train", type=Path, required=True, help="Training data JSONL")
    parser.add_argument("--val", type=Path, required=True, help="Validation data JSONL")
    parser.add_argument(
        "--output", type=Path, default=Path("artifacts/dl"), help="Output directory"
    )
    parser.add_argument("--epochs", type=int, default=50, help="Training epochs")
    parser.add_argument("--batch-size", type=int, default=16, help="Batch size")
    parser.add_argument("--lr", type=float, default=0.001, help="Learning rate")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")

    args = parser.parse_args()

    result = train_binary_model(
        train_path=args.train,
        val_path=args.val,
        output_dir=args.output,
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        seed=args.seed,
    )

    print("\n📊 Training Results:")
    print(json.dumps(result, indent=2))
