"""Evaluation script for transformer model on test and OOD datasets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import torch
from torch.utils.data import DataLoader

from ml.models.transformer import SimpleVocab, build_model
from ml.train_transformer import JsonlDataset, _load_jsonl, build_records


def load_model(
    checkpoint_path: Path, device: torch.device
) -> tuple[Any, SimpleVocab, list[str], dict]:
    """Load model from checkpoint."""
    ckpt = torch.load(checkpoint_path, map_location=device, weights_only=False)

    vocab_data = ckpt.get("vocab", {})
    if isinstance(vocab_data, dict) and "token_to_id" in vocab_data:
        vocab = SimpleVocab.from_dict(vocab_data)
    else:
        vocab = SimpleVocab(token_to_id=vocab_data, id_to_token=list(vocab_data.keys()))

    model = build_model(
        model_name=ckpt.get("model_name", "small"),
        num_categories=len(ckpt["category_vocab"]),
        vocab_size=vocab.size,
        max_len=ckpt["max_len"],
        random_init=True,
    )
    model.load_state_dict(ckpt["model_state_dict"])
    model.to(device)
    model.eval()

    return model, vocab, ckpt["category_vocab"], ckpt


def evaluate_dataset(
    model: Any,
    loader: DataLoader,
    device: torch.device,
    categories: list[str],
    temperature_risk: float = 1.0,
) -> dict[str, Any]:
    """Evaluate model on a dataset."""
    from sklearn.metrics import (
        accuracy_score,
        confusion_matrix,
        f1_score,
        precision_recall_fscore_support,
        roc_auc_score,
    )

    model.eval()
    all_risk_preds = []
    all_risk_probs = []
    all_risk_true = []
    all_cat_preds = []
    all_cat_true = []
    cat_dim = len(categories)
    has_categories = cat_dim > 0

    with torch.no_grad():
        for batch in loader:
            input_ids = batch["input_ids"].to(device)
            attention = batch["attention_mask"].to(device)
            cat_labels = batch["category_labels"]
            risk_labels = batch["risk_label"]

            cat_logits, risk_logit = model(input_ids=input_ids, attention_mask=attention)

            # Risk predictions
            risk_probs = torch.sigmoid(risk_logit / temperature_risk)
            risk_preds = (risk_probs >= 0.5).int()

            all_risk_probs.extend(risk_probs.cpu().tolist())
            all_risk_preds.extend(risk_preds.cpu().tolist())
            all_risk_true.extend(risk_labels.int().tolist())

            if has_categories:
                # Category predictions (multi-label)
                cat_probs = torch.sigmoid(cat_logits)
                cat_preds = (cat_probs >= 0.5).int()

                all_cat_preds.extend(cat_preds.cpu().tolist())
                all_cat_true.extend(cat_labels.int().tolist())

    # Risk metrics
    metrics = {"risk": {}}

    # Filter out -1 labels (UNCERTAIN)
    valid_idx = [i for i, l in enumerate(all_risk_true) if l != -1]
    if valid_idx:
        filtered_true = [all_risk_true[i] for i in valid_idx]
        filtered_preds = [all_risk_preds[i] for i in valid_idx]
        filtered_probs = [all_risk_probs[i] for i in valid_idx]

        metrics["risk"]["accuracy"] = accuracy_score(filtered_true, filtered_preds)
        metrics["risk"]["f1"] = f1_score(filtered_true, filtered_preds, zero_division=0)

        # Confusion matrix
        cm = confusion_matrix(filtered_true, filtered_preds, labels=[0, 1])
        metrics["risk"]["confusion_matrix"] = cm.tolist()
        metrics["risk"]["tn"] = int(cm[0, 0])
        metrics["risk"]["fp"] = int(cm[0, 1])
        metrics["risk"]["fn"] = int(cm[1, 0])
        metrics["risk"]["tp"] = int(cm[1, 1])

        # AUROC (only if both classes present)
        unique_labels = set(filtered_true)
        if len(unique_labels) > 1:
            try:
                metrics["risk"]["auroc"] = roc_auc_score(filtered_true, filtered_probs)
            except ValueError:
                metrics["risk"]["auroc"] = None
        else:
            metrics["risk"]["auroc"] = None
            metrics["risk"]["note"] = f"Only class {list(unique_labels)[0]} present in data"

    # Category metrics
    if has_categories and all_cat_true and all_cat_preds:
        if any(len(row) != cat_dim for row in all_cat_true):
            has_categories = False
        if any(len(row) != cat_dim for row in all_cat_preds):
            has_categories = False
        if has_categories:
            try:
                all_cat_true = [[1 if int(v) else 0 for v in row] for row in all_cat_true]
                all_cat_preds = [[1 if int(v) else 0 for v in row] for row in all_cat_preds]
            except (TypeError, ValueError):
                has_categories = False

    if has_categories and all_cat_true and all_cat_preds:
        try:
            precision, recall, f1, support = precision_recall_fscore_support(
                all_cat_true, all_cat_preds, average=None, zero_division=0
            )

            metrics["category"] = {
                "per_class": {},
                "macro_f1": float(
                    f1_score(all_cat_true, all_cat_preds, average="macro", zero_division=0)
                ),
                "micro_f1": float(
                    f1_score(all_cat_true, all_cat_preds, average="micro", zero_division=0)
                ),
            }

            for i, cat in enumerate(categories):
                metrics["category"]["per_class"][cat] = {
                    "precision": float(precision[i]) if i < len(precision) else 0.0,
                    "recall": float(recall[i]) if i < len(recall) else 0.0,
                    "f1": float(f1[i]) if i < len(f1) else 0.0,
                    "support": int(support[i]) if i < len(support) else 0,
                }
        except ValueError:
            metrics["category"] = {"per_class": {}, "macro_f1": 0.0, "micro_f1": 0.0}
            metrics["category"]["note"] = "invalid category labels in dataset"
    else:
        metrics["category"] = {"per_class": {}, "macro_f1": 0.0, "micro_f1": 0.0}
        if not has_categories:
            metrics["category"]["note"] = "no categories in checkpoint"
        else:
            metrics["category"]["note"] = "no category labels in dataset"

    return metrics


def print_metrics(metrics: dict, dataset_name: str) -> None:
    """Pretty print evaluation metrics."""
    print(f"\n{'='*60}")
    print(f"  {dataset_name} Evaluation Results")
    print(f"{'='*60}")

    # Risk metrics
    risk = metrics.get("risk", {})
    print("\n📊 Risk Classification (TP vs FP)")
    print(f"   Accuracy:  {risk.get('accuracy', 0):.4f}")
    print(f"   F1 Score:  {risk.get('f1', 0):.4f}")
    if risk.get("auroc") is not None:
        print(f"   AUROC:     {risk['auroc']:.4f}")
    else:
        print(f"   AUROC:     N/A ({risk.get('note', 'single class')})")

    print("\n   Confusion Matrix:")
    print(f"   {'':>15} Pred FP  Pred TP")
    print(f"   {'Actual FP':>15}  {risk.get('tn', 0):>5}    {risk.get('fp', 0):>5}")
    print(f"   {'Actual TP':>15}  {risk.get('fn', 0):>5}    {risk.get('tp', 0):>5}")

    # Category metrics
    cat = metrics.get("category", {})
    print("\n📁 Category Classification")
    print(f"   Macro F1:  {cat.get('macro_f1', 0):.4f}")
    print(f"   Micro F1:  {cat.get('micro_f1', 0):.4f}")

    per_class = cat.get("per_class", {})
    if not per_class:
        note = cat.get("note", "no category metrics available")
        print(f"   (skipped) {note}")
        return

    print("\n   Per-Category Performance:")
    print(f"   {'Category':<30} {'Prec':>6} {'Rec':>6} {'F1':>6} {'Support':>8}")
    print(f"   {'-'*58}")

    for cat_name, cat_metrics in sorted(per_class.items(), key=lambda x: -x[1].get("f1", 0)):
        print(
            f"   {cat_name:<30} {cat_metrics['precision']:>6.2f} {cat_metrics['recall']:>6.2f} "
            f"{cat_metrics['f1']:>6.2f} {cat_metrics['support']:>8}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate transformer model")
    parser.add_argument("--checkpoint", required=True, help="Path to model checkpoint")
    parser.add_argument("--test", help="Path to test JSONL file")
    parser.add_argument("--ood", help="Path to OOD test JSONL file")
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--output", help="Output JSON file for metrics")
    args = parser.parse_args()

    device = torch.device(args.device)
    model, vocab, categories, ckpt = load_model(Path(args.checkpoint), device)

    category_to_id = {cat: idx for idx, cat in enumerate(categories)}
    max_len = ckpt["max_len"]
    temperature_risk = ckpt.get("temperature_risk", 1.0)

    all_metrics = {}

    for dataset_name, dataset_path in [("test", args.test), ("ood", args.ood)]:
        if not dataset_path:
            continue

        items = _load_jsonl(Path(dataset_path))
        records = build_records(items)

        if not records:
            print(f"⚠️ No valid records in {dataset_name} dataset")
            continue

        dataset = JsonlDataset(records, vocab, category_to_id, max_len)
        loader = DataLoader(dataset, batch_size=args.batch_size, shuffle=False)

        metrics = evaluate_dataset(model, loader, device, categories, temperature_risk)
        all_metrics[dataset_name] = metrics

        print_metrics(metrics, dataset_name.upper())

    if args.output:
        Path(args.output).write_text(json.dumps(all_metrics, indent=2))
        print(f"\n✅ Metrics saved to {args.output}")


if __name__ == "__main__":
    main()
