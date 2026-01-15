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

from rag.dl.dataset import PairExample, Vocab, build_pairs
from rag.dl.models import DualEncoder, EncoderConfig, batch_lengths


class PairDataset(Dataset[PairExample]):
    def __init__(self, pairs: list[PairExample], vocab: Vocab, max_len: int) -> None:
        self.pairs = pairs
        self.vocab = vocab
        self.max_len = max_len

    def __len__(self) -> int:
        return len(self.pairs)

    def __getitem__(self, idx: int) -> dict[str, list[int]]:
        item = self.pairs[idx]
        return {
            "vuln": self.vocab.encode(item.vuln_text, self.max_len),
            "fixed": self.vocab.encode(item.fixed_text, self.max_len),
        }


def _collate_pairs(batch: list[dict[str, list[int]]]) -> dict[str, torch.Tensor]:
    vuln = torch.tensor([item["vuln"] for item in batch], dtype=torch.long)
    fixed = torch.tensor([item["fixed"] for item in batch], dtype=torch.long)
    return {"vuln": vuln, "fixed": fixed}


def _load_pairs(path: Path) -> list[PairExample]:
    pairs: list[PairExample] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        data = json.loads(line)
        pairs.append(
            PairExample(
                pair_id=data["pair_id"],
                vuln_text=data["vuln_text"],
                fixed_text=data["fixed_text"],
                rule_id=data.get("rule_id"),
                category=data.get("category"),
                metadata=data.get("metadata", {}),
            )
        )
    return pairs


def _info_nce(vuln: torch.Tensor, fixed: torch.Tensor, temperature: float = 0.07) -> torch.Tensor:
    logits = torch.matmul(vuln, fixed.T) / temperature
    labels = torch.arange(logits.size(0), device=logits.device)
    loss = (
        nn.functional.cross_entropy(logits, labels) + nn.functional.cross_entropy(logits.T, labels)
    ) / 2
    return loss


def train_embeddings(args: argparse.Namespace) -> Path:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    pairs_path = Path(args.pairs)
    if not pairs_path.exists():
        build_pairs(pairs_path)
    pairs = _load_pairs(pairs_path)
    if args.max_pairs:
        pairs = pairs[: args.max_pairs]

    vocab = Vocab.build(
        [p.vuln_text for p in pairs] + [p.fixed_text for p in pairs], max_size=args.vocab_size
    )
    dataset = PairDataset(pairs, vocab, args.max_len)
    loader = DataLoader(
        dataset, batch_size=args.batch_size, shuffle=True, collate_fn=_collate_pairs
    )

    config = EncoderConfig(
        vocab_size=len(vocab.token_to_id),
        embed_dim=args.embed_dim,
        hidden_dim=args.hidden_dim,
        max_len=args.max_len,
    )
    model = DualEncoder(config)
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
            vuln = batch["vuln"].to(device)
            fixed = batch["fixed"].to(device)
            vuln_emb = model(vuln, batch_lengths(vuln))
            fixed_emb = model(fixed, batch_lengths(fixed))
            loss = _info_nce(vuln_emb, fixed_emb)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

    model_path = out_dir / "embeddings_model.pt"
    torch.save(
        {
            "state_dict": model.state_dict(),
            "config": config.__dict__,
        },
        model_path,
    )
    vocab_path = out_dir / "vocab.json"
    vocab_path.write_text(json.dumps(vocab.to_json(), indent=2), encoding="utf-8")
    meta_path = out_dir / "embeddings_meta.json"
    meta_path.write_text(
        json.dumps(
            {
                "created_at": datetime.now(UTC).isoformat(),
                "seed": args.seed,
                "embed_dim": args.embed_dim,
                "hidden_dim": args.hidden_dim,
                "max_len": args.max_len,
                "vocab_size": len(vocab.token_to_id),
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
    parser = argparse.ArgumentParser(description="Train a dual-encoder embeddings model.")
    parser.add_argument("--pairs", default="artifacts/dl/pairs.jsonl")
    parser.add_argument("--out-dir", default=os.environ.get("DL_ARTIFACTS_DIR", "artifacts/dl"))
    # Improved hyperparameters: lower LR, more epochs for better convergence
    parser.add_argument(
        "--epochs",
        type=int,
        default=_env_int("DL_EPOCHS", 10),
        help="Number of training epochs (env: DL_EPOCHS)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=_env_int("DL_BATCH_SIZE", 16),
        help="Batch size (env: DL_BATCH_SIZE)",
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
    parser.add_argument("--embed-dim", type=int, default=64)
    parser.add_argument("--hidden-dim", type=int, default=96)
    parser.add_argument("--max-len", type=int, default=96)
    parser.add_argument("--vocab-size", type=int, default=5000)
    parser.add_argument("--max-pairs", type=int, default=200)
    parser.add_argument(
        "--warmup-steps",
        type=int,
        default=_env_int("DL_WARMUP_STEPS", 100),
        help="Learning rate warmup steps (env: DL_WARMUP_STEPS)",
    )
    parser.add_argument(
        "--weight-decay",
        type=float,
        default=_env_float("DL_WEIGHT_DECAY", 0.01),
        help="Weight decay for regularization (env: DL_WEIGHT_DECAY)",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    train_embeddings(args)


if __name__ == "__main__":
    main()
