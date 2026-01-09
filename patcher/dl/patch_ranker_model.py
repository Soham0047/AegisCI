from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

import torch
from torch import nn

from patcher.dl.features import extract_features


@dataclass
class RankerBundle:
    model: nn.Module
    feature_names: list[str]
    input_dim: int


def score_candidates(candidates: list[object]) -> list[float] | None:
    bundle = load_ranker()
    if bundle is None:
        return None
    scores = []
    for candidate in candidates:
        features = extract_features(candidate)
        vector = torch.tensor(features.values, dtype=torch.float32)
        with torch.no_grad():
            score = bundle.model(vector.unsqueeze(0)).squeeze(0).item()
        scores.append(score)
    return scores


@lru_cache(maxsize=1)
def load_ranker() -> RankerBundle | None:
    artifacts = Path(os.environ.get("DL_ARTIFACTS_DIR", "artifacts/dl"))
    model_path = artifacts / "patch_ranker.pt"
    meta_path = artifacts / "patch_ranker_meta.json"
    if not model_path.exists() or not meta_path.exists():
        return None
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    input_dim = int(meta.get("input_dim", 0))
    if input_dim <= 0:
        return None
    model = PatchRankerModel(input_dim=input_dim, hidden_dim=int(meta.get("hidden_dim", 16)))
    payload = torch.load(model_path, map_location="cpu")
    model.load_state_dict(payload.get("state_dict", {}))
    model.eval()
    return RankerBundle(
        model=model, feature_names=meta.get("feature_names", []), input_dim=input_dim
    )


class PatchRankerModel(nn.Module):
    def __init__(self, input_dim: int, hidden_dim: int = 16) -> None:
        super().__init__()
        self.hidden_dim = hidden_dim
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


def save_ranker(model: PatchRankerModel, out_dir: Path, feature_names: list[str]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    model_path = out_dir / "patch_ranker.pt"
    torch.save({"state_dict": model.state_dict()}, model_path)
    meta_path = out_dir / "patch_ranker_meta.json"
    meta_path.write_text(
        json.dumps(
            {
                "created_at": datetime.now(UTC).isoformat(),
                "input_dim": len(feature_names),
                "hidden_dim": model.hidden_dim,
                "feature_names": feature_names,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def synthetic_training_data(candidates: list[object]) -> tuple[torch.Tensor, torch.Tensor]:
    features = [extract_features(candidate).values for candidate in candidates]
    labels = []
    for candidate in candidates:
        labels.append(1.0 if candidate.validated else 0.0)
    return torch.tensor(features, dtype=torch.float32), torch.tensor(labels, dtype=torch.float32)
