from __future__ import annotations

import argparse
import json
import math
import os
import random
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import torch
from torch import nn
from torch.utils.data import DataLoader

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from ml.data.gnn_collate import collate_graph_samples
from ml.data.gnn_dataset import build_graph_samples
from ml.graphs.common import IDENT_BUCKETS, NODE_TYPE_BUCKETS
from ml.models.gnn import GraphClassifier


def set_seed(seed: int) -> None:
    random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)


def compute_metrics(
    risk_labels: list[int],
    risk_probs: list[float],
    cat_labels: list[int],
    cat_logits: list[list[float]],
    num_categories: int,
) -> dict[str, Any]:
    try:
        from sklearn.metrics import accuracy_score, f1_score, roc_auc_score
    except ImportError:  # pragma: no cover
        return {"macro_f1": 0.0, "risk_auroc": float("nan"), "risk_accuracy": 0.0}

    macro_f1 = 0.0
    if num_categories <= 0:
        cat_logits = []
        cat_labels = []
    if num_categories > 0 and cat_logits and cat_labels:
        filtered: list[tuple[int, list[float]]] = []
        for label, row in zip(cat_labels, cat_logits):
            if len(row) >= num_categories:
                filtered.append((label, row))
        if filtered:
            labels, rows = zip(*filtered)
            try:
                cat_preds = [
                    int(max(range(num_categories), key=lambda i: row[i])) for row in rows
                ]
                macro_f1 = f1_score(list(labels), cat_preds, average="macro", zero_division=0)
            except ValueError:
                macro_f1 = 0.0

    risk_auroc = float("nan")
    risk_accuracy = 0.0
    if risk_labels:
        if len(set(risk_labels)) > 1:
            risk_auroc = roc_auc_score(risk_labels, risk_probs)
        risk_preds = [1 if p >= 0.5 else 0 for p in risk_probs]
        risk_accuracy = accuracy_score(risk_labels, risk_preds)

    return {
        "macro_f1": float(macro_f1),
        "risk_auroc": float(risk_auroc),
        "risk_accuracy": float(risk_accuracy),
    }


def evaluate(
    model: GraphClassifier,
    loader: DataLoader,
    device: torch.device,
    num_categories: int,
) -> dict[str, Any]:
    model.eval()
    all_risk_labels: list[int] = []
    all_risk_probs: list[float] = []
    all_cat_labels: list[int] = []
    all_cat_logits: list[list[float]] = []

    with torch.no_grad():
        for batch in loader:
            batch = move_batch(batch, device)
            risk_logit, cat_logits = model(batch)
            risk_prob = torch.sigmoid(risk_logit)
            all_risk_labels.extend(batch.risk_labels.int().tolist())
            all_risk_probs.extend(risk_prob.cpu().tolist())
            if num_categories > 0:
                all_cat_labels.extend(batch.category_labels.int().tolist())
                all_cat_logits.extend(cat_logits.cpu().tolist())

    return compute_metrics(
        all_risk_labels, all_risk_probs, all_cat_labels, all_cat_logits, num_categories
    )


def move_batch(batch, device: torch.device):
    batch.node_type_ids = batch.node_type_ids.to(device)
    batch.ident_hash_ids = batch.ident_hash_ids.to(device)
    batch.literal_flags = batch.literal_flags.to(device)
    batch.node_depth = batch.node_depth.to(device)
    batch.edge_index = batch.edge_index.to(device)
    batch.batch_index = batch.batch_index.to(device)
    batch.risk_labels = batch.risk_labels.to(device)
    batch.category_labels = batch.category_labels.to(device)
    return batch


def train(args: argparse.Namespace) -> None:
    set_seed(args.seed)
    if args.deterministic:
        torch.use_deterministic_algorithms(True)
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False

    train_samples, train_skipped = build_graph_samples(
        Path(args.train),
        max_nodes=args.max_nodes,
        max_edges=args.max_edges,
        default_lang=args.lang,
    )
    val_samples, val_skipped = build_graph_samples(
        Path(args.val),
        max_nodes=args.max_nodes,
        max_edges=args.max_edges,
        default_lang=args.lang,
    )

    category_vocab = sorted({sample.category for sample in train_samples if sample.category})
    category_to_id = {cat: idx for idx, cat in enumerate(category_vocab)}

    train_loader = DataLoader(
        train_samples,
        batch_size=args.batch_size,
        shuffle=True,
        collate_fn=lambda samples: collate_graph_samples(samples, category_to_id),
    )
    val_loader = DataLoader(
        val_samples,
        batch_size=args.batch_size,
        shuffle=False,
        collate_fn=lambda samples: collate_graph_samples(samples, category_to_id),
    )

    device = torch.device(args.device)
    model = GraphClassifier(
        num_categories=len(category_vocab),
        hidden_dim=args.hidden_dim,
        num_layers=args.layers,
        dropout=args.dropout,
    ).to(device)

    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr)
    risk_loss_fn = nn.BCEWithLogitsLoss()
    cat_loss_fn = None
    cat_weight = 0.0
    if category_vocab and args.cat_weight > 0:
        cat_loss_fn = nn.CrossEntropyLoss(ignore_index=-1)
        cat_weight = args.cat_weight

    best_score = -1.0
    best_score_metric = "macro_f1"
    best_state: dict[str, torch.Tensor] = {}
    metrics_history: list[dict[str, Any]] = []
    patience_counter = 0

    for epoch in range(1, args.epochs + 1):
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
            loss = args.risk_weight * risk_loss + cat_weight * cat_loss
            loss.backward()
            optimizer.step()
            total_loss += float(loss.item())

        val_metrics = evaluate(model, val_loader, device, len(category_vocab))
        val_metrics["epoch"] = epoch
        val_metrics["train_loss"] = total_loss / max(len(train_loader), 1)
        metrics_history.append(val_metrics)
        print(
            f"epoch={epoch:2d} loss={val_metrics['train_loss']:.4f} "
            f"macro_f1={val_metrics['macro_f1']:.4f} "
            f"auroc={val_metrics['risk_auroc']:.4f}"
        )

        score = val_metrics["macro_f1"]
        score_metric = "macro_f1"
        if not category_vocab:
            score = val_metrics.get("risk_auroc", float("nan"))
            score_metric = "risk_auroc"
            if math.isnan(score):
                score = val_metrics.get("risk_accuracy", 0.0)
                score_metric = "risk_accuracy"
        if score > best_score:
            best_score = score
            best_score_metric = score_metric
            best_state = {k: v.cpu() for k, v in model.state_dict().items()}
            patience_counter = 0
        else:
            patience_counter += 1
            if args.patience and patience_counter >= args.patience:
                print(f"Early stopping at epoch {epoch}")
                break

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    checkpoint = {
        "model_state_dict": best_state,
        "category_vocab": category_vocab,
        "node_type_buckets": NODE_TYPE_BUCKETS,
        "ident_buckets": IDENT_BUCKETS,
        "hidden_dim": args.hidden_dim,
        "layers": args.layers,
        "dropout": args.dropout,
        "created_at": datetime.utcnow().isoformat(),
        "best_score_metric": best_score_metric,
    }
    torch.save(checkpoint, output_path)

    metrics_path = Path(args.metrics_out)
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.write_text(json.dumps(metrics_history, indent=2), encoding="utf-8")

    print(f"Skipped train samples: {train_skipped}")
    print(f"Skipped val samples: {val_skipped}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train GNN baseline for risk scoring")
    parser.add_argument("--train", required=True)
    parser.add_argument("--val", required=True)
    parser.add_argument("--lang", default="python")
    parser.add_argument("--epochs", type=int, default=5)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--lr", type=float, default=2e-3)
    parser.add_argument("--hidden-dim", type=int, default=128)
    parser.add_argument("--layers", type=int, default=2)
    parser.add_argument("--dropout", type=float, default=0.1)
    parser.add_argument("--max-nodes", type=int, default=2048)
    parser.add_argument("--max-edges", type=int, default=8192)
    parser.add_argument("--risk-weight", type=float, default=1.0)
    parser.add_argument("--cat-weight", type=float, default=1.0)
    parser.add_argument("--patience", type=int, default=3)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--deterministic", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--output", default="artifacts/gnn_v1.pt")
    parser.add_argument("--metrics-out", default="artifacts/gnn_v1_metrics.json")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    train(args)


if __name__ == "__main__":
    main()
