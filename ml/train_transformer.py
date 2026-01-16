# Dataset summary (datasets/transformer/*.jsonl):
# keys: sample_id, tokens (list[str]), token_ids (None), label (0/1), verdict (TP/FP/UNCERTAIN),
# category (str), features (dict). Labels: category (single) and label (risk 0/1).
# Risk label uses `label` when present; UNCERTAIN samples are excluded from training/eval.

from __future__ import annotations

import argparse
import json
import math
import os
import random
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import torch
from torch import nn
from torch.optim.lr_scheduler import LambdaLR
from torch.utils.data import DataLoader, Dataset

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.models.transformer import SimpleVocab, build_model, tokenize_text  # noqa: E402


class FocalLoss(nn.Module):
    """Focal Loss for handling class imbalance."""

    def __init__(self, alpha: float = 0.25, gamma: float = 2.0, reduction: str = "mean"):
        super().__init__()
        self.alpha = alpha
        self.gamma = gamma
        self.reduction = reduction

    def forward(self, inputs: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        # Compute BCE loss
        bce_loss = nn.functional.binary_cross_entropy_with_logits(inputs, targets, reduction="none")

        # Compute pt (probability of correct class)
        probs = torch.sigmoid(inputs)
        pt = torch.where(targets == 1, probs, 1 - probs)

        # Compute focal weight
        focal_weight = (1 - pt) ** self.gamma

        # Apply alpha weighting
        alpha_weight = torch.where(targets == 1, self.alpha, 1 - self.alpha)

        focal_loss = alpha_weight * focal_weight * bce_loss

        if self.reduction == "mean":
            return focal_loss.mean()
        elif self.reduction == "sum":
            return focal_loss.sum()
        return focal_loss


def get_linear_schedule_with_warmup(
    optimizer: torch.optim.Optimizer,
    num_warmup_steps: int,
    num_training_steps: int,
) -> LambdaLR:
    """Create a schedule with linear warmup and linear decay."""

    def lr_lambda(current_step: int) -> float:
        if current_step < num_warmup_steps:
            return float(current_step) / float(max(1, num_warmup_steps))
        return max(
            0.0,
            float(num_training_steps - current_step)
            / float(max(1, num_training_steps - num_warmup_steps)),
        )

    return LambdaLR(optimizer, lr_lambda)


@dataclass
class Record:
    tokens: list[str]
    categories: list[str]
    risk_label: int


def set_seed(seed: int) -> None:
    random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [json.loads(line) for line in lines]


def _extract_tokens(item: dict[str, Any]) -> list[str]:
    tokens = item.get("tokens")
    if isinstance(tokens, list) and tokens:
        return [str(t) for t in tokens]
    parts = [
        item.get("context_before") or "",
        item.get("code_snippet") or "",
        item.get("context_after") or "",
    ]
    text = "\n".join([p for p in parts if p])
    return tokenize_text(text)


def _extract_categories(item: dict[str, Any]) -> list[str]:
    if isinstance(item.get("categories"), list):
        return [str(c) for c in item["categories"] if c]
    if item.get("category"):
        return [str(item["category"])]
    gold = item.get("gold_labels") or {}
    if isinstance(gold, dict) and gold.get("category"):
        return [str(gold["category"])]
    return []


def _extract_risk_label(item: dict[str, Any]) -> int | None:
    # Check for direct label field
    if item.get("label") is not None:
        try:
            return int(item["label"])
        except (TypeError, ValueError):
            return None

    # Check for is_vulnerable boolean field
    if item.get("is_vulnerable") is not None:
        return 1 if item["is_vulnerable"] else 0

    # Check for verdict field
    verdict = item.get("verdict")
    if verdict is None:
        gold = item.get("gold_labels") or {}
        verdict = gold.get("verdict")
    if not verdict:
        return None
    verdict = str(verdict).upper()
    if verdict == "UNCERTAIN":
        return None
    return 1 if verdict == "TP" else 0


def build_records(items: Iterable[dict[str, Any]]) -> list[Record]:
    records: list[Record] = []
    for item in items:
        categories = _extract_categories(item)
        risk_label = _extract_risk_label(item)
        if risk_label is None:
            continue
        tokens = _extract_tokens(item)
        if not tokens:
            continue
        records.append(Record(tokens=tokens, categories=categories, risk_label=risk_label))
    return records


class JsonlDataset(Dataset[dict[str, torch.Tensor]]):
    def __init__(
        self,
        records: list[Record],
        vocab: SimpleVocab,
        category_to_id: dict[str, int],
        max_len: int,
    ) -> None:
        self.records = records
        self.vocab = vocab
        self.category_to_id = category_to_id
        self.max_len = max_len

    def __len__(self) -> int:
        return len(self.records)

    def __getitem__(self, idx: int) -> dict[str, torch.Tensor]:
        record = self.records[idx]
        input_ids, attention = self.vocab.encode(record.tokens, self.max_len)
        label_vec = torch.zeros(len(self.category_to_id), dtype=torch.float32)
        for cat in record.categories:
            if cat in self.category_to_id:
                label_vec[self.category_to_id[cat]] = 1.0
        return {
            "input_ids": torch.tensor(input_ids, dtype=torch.long),
            "attention_mask": torch.tensor(attention, dtype=torch.long),
            "category_labels": label_vec,
            "risk_label": torch.tensor(record.risk_label, dtype=torch.float32),
        }


def _compute_metrics(
    y_true_cat: list[list[int]],
    y_pred_cat: list[list[float]],
    y_true_risk: list[int],
    y_pred_risk: list[float],
    categories: list[str],
) -> dict[str, Any]:
    try:
        from sklearn.metrics import accuracy_score, precision_recall_fscore_support, roc_auc_score
    except ImportError:  # pragma: no cover - fallback for minimal envs
        precision_recall_fscore_support = None
        roc_auc_score = None
        accuracy_score = None

    metrics: dict[str, Any] = {"per_category": {}}
    cat_dim = len(categories)
    has_categories = cat_dim > 0 and y_true_cat and y_pred_cat
    if has_categories:
        if any(len(row) != cat_dim for row in y_true_cat):
            has_categories = False
        if any(len(row) != cat_dim for row in y_pred_cat):
            has_categories = False
        if has_categories:
            try:
                y_true_cat = [[1 if int(v) else 0 for v in row] for row in y_true_cat]
                y_pred_cat = [[float(v) for v in row] for row in y_pred_cat]
            except (TypeError, ValueError):
                has_categories = False

    if precision_recall_fscore_support and has_categories:
        pred_bin = [[1 if p >= 0.5 else 0 for p in row] for row in y_pred_cat]
        try:
            precision, recall, f1, _ = precision_recall_fscore_support(
                y_true_cat, pred_bin, average=None, zero_division=0
            )
            for idx, category in enumerate(categories):
                metrics["per_category"][category] = {
                    "precision": float(precision[idx]),
                    "recall": float(recall[idx]),
                    "f1": float(f1[idx]),
                }
            macro = precision_recall_fscore_support(
                y_true_cat, pred_bin, average="macro", zero_division=0
            )
            metrics["macro_f1"] = float(macro[2])
        except ValueError:
            metrics["macro_f1"] = 0.0
    else:
        metrics["macro_f1"] = 0.0

    # Filter out UNCERTAIN labels (-1) for risk metrics
    valid_indices = [i for i, label in enumerate(y_true_risk) if label in (0, 1)]
    if valid_indices and roc_auc_score:
        filtered_true = [y_true_risk[i] for i in valid_indices]
        filtered_pred = [y_pred_risk[i] for i in valid_indices]

        # Check if we have both classes
        unique_labels = set(filtered_true)
        if len(unique_labels) > 1:
            try:
                metrics["risk_auroc"] = float(roc_auc_score(filtered_true, filtered_pred))
            except ValueError:
                metrics["risk_auroc"] = float("nan")
        else:
            metrics["risk_auroc"] = float("nan")  # Only one class present

        # Also compute accuracy
        if accuracy_score:
            risk_preds = [1 if p >= 0.5 else 0 for p in filtered_pred]
            metrics["risk_accuracy"] = float(accuracy_score(filtered_true, risk_preds))
    else:
        metrics["risk_auroc"] = float("nan")
        metrics["risk_accuracy"] = 0.0

    return metrics


def fit_temperature(risk_logits: torch.Tensor, risk_labels: torch.Tensor) -> float:
    temperature = torch.nn.Parameter(torch.ones(1))
    optimizer = torch.optim.LBFGS([temperature], max_iter=50)
    loss_fn = nn.BCEWithLogitsLoss()
    risk_labels = risk_labels.float()

    def closure() -> torch.Tensor:
        optimizer.zero_grad()
        loss = loss_fn(risk_logits / temperature, risk_labels)
        loss.backward()
        return loss

    optimizer.step(closure)
    return float(max(temperature.item(), 1e-3))


def _evaluate(
    model: nn.Module,
    loader: DataLoader,
    device: torch.device,
    categories: list[str],
) -> tuple[dict[str, Any], torch.Tensor, torch.Tensor]:
    model.eval()
    all_cat_probs: list[list[float]] = []
    all_cat_true: list[list[int]] = []
    all_risk_probs: list[float] = []
    all_risk_true: list[int] = []
    all_risk_logits: list[float] = []

    with torch.no_grad():
        for batch in loader:
            input_ids = batch["input_ids"].to(device)
            attention = batch["attention_mask"].to(device)
            cat_labels = batch["category_labels"].to(device)
            risk_labels = batch["risk_label"].to(device)

            cat_logits, risk_logit = model(input_ids=input_ids, attention_mask=attention)
            cat_probs = torch.sigmoid(cat_logits)
            risk_probs = torch.sigmoid(risk_logit)

            all_cat_probs.extend(cat_probs.cpu().tolist())
            all_cat_true.extend(cat_labels.cpu().int().tolist())
            all_risk_probs.extend(risk_probs.cpu().tolist())
            all_risk_true.extend(risk_labels.cpu().int().tolist())
            all_risk_logits.extend(risk_logit.cpu().tolist())

    metrics = _compute_metrics(
        y_true_cat=all_cat_true,
        y_pred_cat=all_cat_probs,
        y_true_risk=all_risk_true,
        y_pred_risk=all_risk_probs,
        categories=categories,
    )
    return metrics, torch.tensor(all_risk_logits), torch.tensor(all_risk_true)


def _git_commit() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True
        )
        return result.stdout.strip()
    except Exception:
        return "unknown"


def _compute_class_weights(records: list[Record], category_to_id: dict[str, int]) -> torch.Tensor:
    """Compute inverse frequency weights for categories."""
    from collections import Counter

    n_classes = len(category_to_id)
    if n_classes == 0:
        return torch.zeros(0)

    counts = Counter()
    for record in records:
        for cat in record.categories:
            if cat in category_to_id:
                counts[category_to_id[cat]] += 1

    weights = torch.ones(n_classes)
    total = sum(counts.values())
    for idx, count in counts.items():
        if count > 0:
            # Inverse frequency weighting with smoothing
            weights[idx] = total / (n_classes * count)

    # Normalize weights to have mean 1
    if weights.numel() > 0:
        weights = weights / weights.mean()
    return weights


def train(args: argparse.Namespace) -> None:
    set_seed(args.seed)
    if args.deterministic:
        torch.use_deterministic_algorithms(True)
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False

    train_items = _load_jsonl(Path(args.train))
    val_items = _load_jsonl(Path(args.val)) if args.val else train_items

    train_records = build_records(train_items)
    val_records = build_records(val_items)
    if args.max_train_samples:
        train_records = train_records[: args.max_train_samples]
    if args.max_val_samples:
        val_records = val_records[: args.max_val_samples]
    if not train_records:
        raise ValueError("No training records found after filtering")
    if not val_records:
        raise ValueError("No validation records found after filtering")

    category_vocab = sorted({cat for record in train_records for cat in record.categories if cat})
    category_to_id = {cat: idx for idx, cat in enumerate(category_vocab)}
    vocab = SimpleVocab.build(record.tokens for record in train_records)

    print(f"Vocab size: {vocab.size}, Categories: {len(category_vocab)}")
    print(f"Train samples: {len(train_records)}, Val samples: {len(val_records)}")

    train_dataset = JsonlDataset(train_records, vocab, category_to_id, args.max_len)
    val_dataset = JsonlDataset(val_records, vocab, category_to_id, args.max_len)

    train_loader = DataLoader(train_dataset, batch_size=args.batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=args.batch_size, shuffle=False)

    device = torch.device(args.device)
    model = build_model(
        model_name=args.model_name,
        num_categories=len(category_vocab),
        vocab_size=vocab.size,
        max_len=args.max_len,
        random_init=not args.pretrained,
    ).to(device)

    # Count parameters
    n_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"Model parameters: {n_params:,}")

    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=0.01)

    # Compute class weights for category loss
    loss_cat: nn.Module | None = None
    if category_vocab and args.cat_weight > 0:
        class_weights = _compute_class_weights(train_records, category_to_id).to(device)
        if class_weights.numel() > 0 and not torch.isnan(class_weights).any():
            loss_cat = nn.BCEWithLogitsLoss(pos_weight=class_weights)
            print(
                "Using weighted BCE for categories (weight range: "
                f"{class_weights.min():.2f} - {class_weights.max():.2f})"
            )
        else:
            loss_cat = None
    if loss_cat is None:
        print("No category labels found; training risk-only head.")

    loss_risk = nn.BCEWithLogitsLoss()

    # Use focal loss for risk classification to handle TP/FP imbalance
    if args.focal_loss:
        loss_risk = FocalLoss(alpha=args.focal_alpha, gamma=args.focal_gamma)
        print(f"Using Focal Loss for risk (alpha={args.focal_alpha}, gamma={args.focal_gamma})")

    # Learning rate scheduler with warmup
    num_training_steps = len(train_loader) * args.epochs
    num_warmup_steps = int(num_training_steps * args.warmup_ratio)
    scheduler = get_linear_schedule_with_warmup(optimizer, num_warmup_steps, num_training_steps)
    print(f"LR Schedule: {num_warmup_steps} warmup steps, {num_training_steps} total steps")

    best_metric = -1.0
    best_state: dict[str, torch.Tensor] = {}
    best_risk_logits = torch.tensor([])
    best_risk_labels = torch.tensor([])
    metrics_history: list[dict[str, Any]] = []
    patience_counter = 0

    for epoch in range(1, args.epochs + 1):
        model.train()
        total_loss = 0.0
        for batch in train_loader:
            input_ids = batch["input_ids"].to(device)
            attention = batch["attention_mask"].to(device)
            cat_labels = batch["category_labels"].to(device)
            risk_labels = batch["risk_label"].to(device)

            optimizer.zero_grad()
            cat_logits, risk_logit = model(input_ids=input_ids, attention_mask=attention)

            # Weighted loss combination - give more weight to risk task initially
            cat_loss = torch.tensor(0.0, device=device)
            if loss_cat is not None and cat_labels.numel() > 0:
                cat_loss = loss_cat(cat_logits, cat_labels)
            risk_loss = loss_risk(risk_logit, risk_labels)
            cat_weight = args.cat_weight if loss_cat is not None else 0.0
            loss = cat_weight * cat_loss + args.risk_weight * risk_loss
            loss.backward()

            # Gradient clipping
            if args.max_grad_norm > 0:
                torch.nn.utils.clip_grad_norm_(model.parameters(), args.max_grad_norm)

            optimizer.step()
            scheduler.step()
            total_loss += float(loss.item())

        val_metrics, risk_logits, risk_labels = _evaluate(model, val_loader, device, category_vocab)
        val_metrics["epoch"] = epoch
        val_metrics["train_loss"] = total_loss / max(len(train_loader), 1)
        val_metrics["lr"] = scheduler.get_last_lr()[0]
        metrics_history.append(val_metrics)

        auroc_str = (
            f"{val_metrics['risk_auroc']:.4f}"
            if not math.isnan(val_metrics.get("risk_auroc", float("nan")))
            else "N/A"
        )
        print(
            f"epoch={epoch:2d} loss={val_metrics['train_loss']:.4f} "
            f"macro_f1={val_metrics['macro_f1']:.4f} auroc={auroc_str} "
            f"lr={val_metrics['lr']:.2e}"
        )

        score = val_metrics.get("macro_f1", 0.0)
        if not category_vocab:
            risk_auroc = val_metrics.get("risk_auroc", float("nan"))
            if not math.isnan(risk_auroc):
                score = risk_auroc
            else:
                score = val_metrics.get("risk_accuracy", 0.0)
        if score > best_metric:
            best_metric = score
            best_state = {k: v.cpu() for k, v in model.state_dict().items()}
            best_risk_logits = risk_logits
            best_risk_labels = risk_labels
            patience_counter = 0
        else:
            patience_counter += 1
            if args.patience > 0 and patience_counter >= args.patience:
                print(
                    f"Early stopping at epoch {epoch} (no improvement for {args.patience} epochs)"
                )
                break

    temperature = fit_temperature(best_risk_logits, best_risk_labels)
    # Clamp temperature to reasonable range
    temperature = max(0.1, min(temperature, 10.0))
    print(f"Fitted temperature: {temperature:.4f}")

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    checkpoint = {
        "model_state_dict": best_state,
        "model_name": args.model_name,
        "category_vocab": category_vocab,
        "vocab": vocab.token_to_id,
        "max_len": args.max_len,
        "temperature_risk": temperature,
        "best_macro_f1": best_metric,
        "epochs_trained": epoch,
        "created_at": datetime.utcnow().isoformat(),
        "git_commit": _git_commit(),
    }
    torch.save(checkpoint, output_path)
    print(f"Model saved to {output_path}")

    metrics_out = Path(args.metrics_out)
    metrics_out.parent.mkdir(parents=True, exist_ok=True)
    metrics_out.write_text(json.dumps(metrics_history, indent=2), encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train transformer baseline for risk scoring")
    parser.add_argument("--train", required=True)
    parser.add_argument("--val", required=False)
    parser.add_argument("--test", required=False)
    parser.add_argument(
        "--model-name", default="small", help="Model size: tiny, small, medium, or HF model name"
    )
    parser.add_argument("--epochs", type=int, default=30)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--max-len", type=int, default=256)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", default="artifacts/transformer_v1.pt")
    parser.add_argument("--metrics-out", default="artifacts/transformer_v1_metrics.json")
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--pretrained", action="store_true", help="Use pretrained weights")
    parser.add_argument(
        "--deterministic",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable deterministic algorithms for reproducibility.",
    )
    parser.add_argument("--max-train-samples", type=int, default=None)
    parser.add_argument("--max-val-samples", type=int, default=None)

    # Training improvements
    parser.add_argument(
        "--warmup-ratio", type=float, default=0.1, help="Warmup ratio for LR scheduler"
    )
    parser.add_argument(
        "--max-grad-norm",
        type=float,
        default=1.0,
        help="Max gradient norm for clipping (0 to disable)",
    )
    parser.add_argument(
        "--patience", type=int, default=7, help="Early stopping patience (0 to disable)"
    )
    parser.add_argument(
        "--focal-loss", action="store_true", help="Use focal loss for risk classification"
    )
    parser.add_argument("--focal-alpha", type=float, default=0.25, help="Focal loss alpha")
    parser.add_argument("--focal-gamma", type=float, default=2.0, help="Focal loss gamma")

    # Loss weighting
    parser.add_argument("--cat-weight", type=float, default=1.0, help="Weight for category loss")
    parser.add_argument("--risk-weight", type=float, default=1.0, help="Weight for risk loss")

    return parser


def main() -> None:
    args = build_parser().parse_args()
    train(args)


if __name__ == "__main__":
    main()
