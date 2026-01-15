from __future__ import annotations

import argparse
import json
import os
import random
from datetime import UTC, datetime
from pathlib import Path

import torch
from torch import nn
from torch.utils.data import DataLoader, Dataset

from rag.dl.dataset import RetrievalTriple, build_retrieval_triples
from rag.dl.models import RerankerMLP, build_pair_features
from rag.embeddings import embed_text


class TripleDataset(Dataset[RetrievalTriple]):
    def __init__(self, triples: list[RetrievalTriple]) -> None:
        self.triples = triples

    def __len__(self) -> int:
        return len(self.triples)

    def __getitem__(self, idx: int) -> RetrievalTriple:
        return self.triples[idx]


def _load_triples(path: Path) -> list[RetrievalTriple]:
    triples: list[RetrievalTriple] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        data = json.loads(line)
        triples.append(
            RetrievalTriple(
                triple_id=data["triple_id"],
                query=data["query"],
                positive_text=data["positive_text"],
                negative_texts=data.get("negative_texts", []),
                positive_chunk_id=data.get("positive_chunk_id", ""),
                metadata=data.get("metadata", {}),
            )
        )
    return triples


def _to_tensor(vec: list[float]) -> torch.Tensor:
    return torch.tensor(vec, dtype=torch.float32)


def train_reranker(args: argparse.Namespace) -> Path:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    triples_path = Path(args.triples)
    if not triples_path.exists():
        build_retrieval_triples(Path(args.store_path), triples_path)
    triples = _load_triples(triples_path)
    if args.max_triples:
        triples = triples[: args.max_triples]

    dataset = TripleDataset(triples)
    loader = DataLoader(dataset, batch_size=1, shuffle=True, collate_fn=lambda batch: batch)

    embedding_dim = len(embed_text("seed"))
    input_dim = embedding_dim * 4
    model = RerankerMLP(input_dim=input_dim, hidden_dim=args.hidden_dim)
    device = torch.device("cpu")
    model.to(device)
    weight_decay = getattr(args, "weight_decay", 0.0)
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=weight_decay)

    random.seed(args.seed)
    torch.manual_seed(args.seed)
    try:
        torch.use_deterministic_algorithms(True)
    except Exception:
        pass

    for _ in range(args.epochs):
        for batch in loader:
            triple = batch[0]
            query_emb = _to_tensor(embed_text(triple.query)).to(device)
            pos_emb = _to_tensor(embed_text(triple.positive_text)).to(device)
            pos_features = build_pair_features(query_emb, pos_emb)
            pos_score = model(pos_features.unsqueeze(0))
            neg_scores = []
            for neg_text in triple.negative_texts:
                neg_emb = _to_tensor(embed_text(neg_text)).to(device)
                neg_features = build_pair_features(query_emb, neg_emb)
                neg_scores.append(model(neg_features.unsqueeze(0)))
            if not neg_scores:
                continue
            neg_scores_tensor = torch.cat(neg_scores)
            loss = torch.mean(nn.functional.softplus(-(pos_score - neg_scores_tensor)))
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

    model_path = out_dir / "reranker_model.pt"
    torch.save(
        {
            "state_dict": model.state_dict(),
            "input_dim": input_dim,
            "embedding_dim": embedding_dim,
        },
        model_path,
    )
    meta_path = out_dir / "reranker_meta.json"
    meta_path.write_text(
        json.dumps(
            {
                "created_at": datetime.now(UTC).isoformat(),
                "seed": args.seed,
                "input_dim": input_dim,
                "embedding_dim": embedding_dim,
                "hidden_dim": args.hidden_dim,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return model_path


def _env_int(name: str, default: int) -> int:
    """Get integer from environment variable or return default."""
    val = os.environ.get(name)
    return int(val) if val else default


def _env_float(name: str, default: float) -> float:
    """Get float from environment variable or return default."""
    val = os.environ.get(name)
    return float(val) if val else default


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train a lightweight reranker model.")
    parser.add_argument("--store-path", default="rag/store/rag.sqlite")
    parser.add_argument("--triples", default="artifacts/dl/triples.jsonl")
    parser.add_argument("--out-dir", default=os.environ.get("DL_ARTIFACTS_DIR", "artifacts/dl"))
    # Improved hyperparameters: lower LR, more epochs for better convergence
    parser.add_argument(
        "--epochs",
        type=int,
        default=_env_int("DL_EPOCHS", 10),
        help="Number of training epochs (env: DL_EPOCHS)",
    )
    parser.add_argument(
        "--lr",
        type=float,
        default=_env_float("DL_LR", 5e-4),
        help="Learning rate (env: DL_LR) - lower default for stability",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=_env_int("DL_SEED", 1337),
        help="Random seed for reproducibility (env: DL_SEED)",
    )
    parser.add_argument("--hidden-dim", type=int, default=64)
    parser.add_argument("--max-triples", type=int, default=200)
    parser.add_argument(
        "--weight-decay",
        type=float,
        default=_env_float("DL_WEIGHT_DECAY", 0.01),
        help="Weight decay for regularization (env: DL_WEIGHT_DECAY)",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    train_reranker(args)


if __name__ == "__main__":
    main()
