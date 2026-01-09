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
    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr)

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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train a dual-encoder embeddings model.")
    parser.add_argument("--pairs", default="artifacts/dl/pairs.jsonl")
    parser.add_argument("--out-dir", default=os.environ.get("DL_ARTIFACTS_DIR", "artifacts/dl"))
    parser.add_argument("--epochs", type=int, default=1)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--embed-dim", type=int, default=64)
    parser.add_argument("--hidden-dim", type=int, default=96)
    parser.add_argument("--max-len", type=int, default=96)
    parser.add_argument("--vocab-size", type=int, default=5000)
    parser.add_argument("--max-pairs", type=int, default=200)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    train_embeddings(args)


if __name__ == "__main__":
    main()
