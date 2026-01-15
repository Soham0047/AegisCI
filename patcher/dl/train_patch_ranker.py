from __future__ import annotations

import argparse
import os
import random
import sqlite3
from pathlib import Path

import torch
from torch import nn

from patcher.dl.features import FEATURE_NAMES, extract_features
from patcher.dl.patch_ranker_model import PatchRankerModel, save_ranker
from patcher.ranker import Candidate


def _synthetic_candidates() -> tuple[list[Candidate], list[float]]:
    return [
        Candidate(
            candidate_id="det-0",
            diff="--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-print('x')\n+print('y')\n",
            source="deterministic",
            diff_ok=True,
            validated=True,
            validation_status="validated",
            metadata={},
        ),
        Candidate(
            candidate_id="llm-0",
            diff="--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-print('x')\n+print('y')\n+print('z')\n",
            source="llm",
            diff_ok=True,
            validated=True,
            validation_status="validated",
            metadata={},
        ),
        Candidate(
            candidate_id="llm-1",
            diff="",
            source="llm",
            diff_ok=False,
            validated=False,
            validation_status="diff invalid",
            metadata={},
        ),
    ], [1.0, 0.0, 0.0]


def _outcome_candidates(
    outcomes_db: Path, artifacts_root: Path
) -> tuple[list[Candidate], list[float]]:
    if not outcomes_db.exists():
        return [], []
    candidates: list[Candidate] = []
    labels: list[float] = []
    conn = sqlite3.connect(outcomes_db)
    rows = conn.execute(
        "SELECT job_id, finding_id, candidate_id, action FROM patch_outcomes"
    ).fetchall()
    conn.close()
    for job_id, _finding_id, candidate_id, action in rows:
        diff_path = artifacts_root / str(job_id) / "final.diff"
        if not diff_path.exists():
            continue
        diff = diff_path.read_text(encoding="utf-8", errors="ignore")
        source = "deterministic" if str(candidate_id).startswith("det-") else "llm"
        candidates.append(
            Candidate(
                candidate_id=str(candidate_id),
                diff=diff,
                source=source,
                diff_ok=bool(diff),
                validated=True,
                validation_status="validated",
                metadata={},
            )
        )
        labels.append(1.0 if action == "accepted" else 0.0)
    return candidates, labels


def train_ranker(args: argparse.Namespace) -> Path:
    random.seed(args.seed)
    torch.manual_seed(args.seed)
    try:
        torch.use_deterministic_algorithms(True)
    except Exception:
        pass

    candidates, labels = _outcome_candidates(Path(args.outcomes_db), Path(args.artifacts_root))
    if not candidates:
        candidates, labels = _synthetic_candidates()
    features = [extract_features(c).values for c in candidates]
    x = torch.tensor(features, dtype=torch.float32)
    y = torch.tensor(labels, dtype=torch.float32)

    model = PatchRankerModel(input_dim=len(FEATURE_NAMES), hidden_dim=args.hidden_dim)
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=args.weight_decay)
    loss_fn = nn.BCEWithLogitsLoss()

    for _ in range(args.epochs):
        logits = model(x).squeeze(-1)
        loss = loss_fn(logits, y)
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

    out_dir = Path(args.out_dir)
    save_ranker(model, out_dir, FEATURE_NAMES)
    return out_dir / "patch_ranker.pt"


def _env_int(name: str, default: int) -> int:
    """Get integer from environment variable or return default."""
    val = os.environ.get(name)
    return int(val) if val else default


def _env_float(name: str, default: float) -> float:
    """Get float from environment variable or return default."""
    val = os.environ.get(name)
    return float(val) if val else default


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train the patch ranker model.")
    parser.add_argument("--out-dir", default=os.environ.get("DL_ARTIFACTS_DIR", "artifacts/dl"))
    # Improved hyperparameters: lower LR, more epochs for better convergence
    parser.add_argument(
        "--epochs",
        type=int,
        default=_env_int("DL_EPOCHS", 20),
        help="Number of training epochs (env: DL_EPOCHS)",
    )
    parser.add_argument(
        "--lr",
        type=float,
        default=_env_float("DL_LR", 5e-3),
        help="Learning rate (env: DL_LR) - lower default for stability",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=_env_int("DL_SEED", 1337),
        help="Random seed for reproducibility (env: DL_SEED)",
    )
    parser.add_argument("--hidden-dim", type=int, default=16)
    parser.add_argument("--outcomes-db", default="backend/data/outcomes.db")
    parser.add_argument("--artifacts-root", default="artifacts/jobs")
    parser.add_argument(
        "--weight-decay",
        type=float,
        default=_env_float("DL_WEIGHT_DECAY", 0.01),
        help="Weight decay for regularization (env: DL_WEIGHT_DECAY)",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    train_ranker(args)


if __name__ == "__main__":
    main()
