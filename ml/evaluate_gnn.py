from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import torch
from torch.utils.data import DataLoader

from ml.data.gnn_collate import collate_graph_samples
from ml.data.gnn_dataset import build_graph_samples
from ml.models.gnn import GraphClassifier
from ml.train_gnn import evaluate


def _load_checkpoint(path: Path, device: torch.device) -> tuple[GraphClassifier, list[str], dict[str, Any]]:
    ckpt = torch.load(path, map_location=device, weights_only=False)
    category_vocab = ckpt.get("category_vocab", [])
    model = GraphClassifier(
        num_categories=len(category_vocab),
        hidden_dim=ckpt.get("hidden_dim", 128),
        num_layers=ckpt.get("layers", 2),
        dropout=ckpt.get("dropout", 0.1),
    ).to(device)
    model.load_state_dict(ckpt["model_state_dict"])
    model.eval()
    return model, category_vocab, ckpt


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate GNN model on test dataset")
    parser.add_argument("--checkpoint", required=True, help="Path to GNN checkpoint")
    parser.add_argument("--test", required=True, help="Path to test JSONL file")
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--max-nodes", type=int, default=2048)
    parser.add_argument("--max-edges", type=int, default=8192)
    parser.add_argument("--lang", default="python")
    parser.add_argument("--output", help="Output JSON file for metrics")
    args = parser.parse_args()

    device = torch.device(args.device)
    model, category_vocab, _ = _load_checkpoint(Path(args.checkpoint), device)
    category_to_id = {cat: idx for idx, cat in enumerate(category_vocab)}

    samples, skipped = build_graph_samples(
        Path(args.test),
        max_nodes=args.max_nodes,
        max_edges=args.max_edges,
        default_lang=args.lang,
    )
    if not samples:
        print("WARNING: No valid graph samples found in test set")
        metrics = {"macro_f1": 0.0, "risk_auroc": float("nan"), "skipped": skipped}
    else:
        loader = DataLoader(
            samples,
            batch_size=args.batch_size,
            shuffle=False,
            collate_fn=lambda items: collate_graph_samples(items, category_to_id),
        )
        metrics = evaluate(model, loader, device, len(category_vocab))
        metrics["skipped"] = skipped

    print(f"GNN eval: macro_f1={metrics.get('macro_f1', 0):.4f} auroc={metrics.get('risk_auroc')}")
    if args.output:
        Path(args.output).write_text(json.dumps(metrics, indent=2), encoding="utf-8")
        print(f"OK: metrics saved to {args.output}")


if __name__ == "__main__":
    main()
