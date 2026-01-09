from __future__ import annotations

import json
import os
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import torch

from rag.dl.models import RerankerMLP, build_pair_features
from rag.embeddings import embed_text


@dataclass
class RerankerBundle:
    model: RerankerMLP
    input_dim: int
    embedding_dim: int


def score_pairs(query: str, docs: Iterable[str]) -> list[float] | None:
    bundle = load_reranker()
    if bundle is None:
        return None
    scores: list[float] = []
    query_emb = torch.tensor(embed_text(query), dtype=torch.float32)
    for doc in docs:
        doc_emb = torch.tensor(embed_text(doc), dtype=torch.float32)
        features = build_pair_features(query_emb, doc_emb)
        with torch.no_grad():
            score = bundle.model(features.unsqueeze(0)).item()
        scores.append(score)
    return scores


@lru_cache(maxsize=1)
def load_reranker() -> RerankerBundle | None:
    artifacts = Path(os.environ.get("DL_ARTIFACTS_DIR", "artifacts/dl"))
    model_path = artifacts / "reranker_model.pt"
    meta_path = artifacts / "reranker_meta.json"
    if not model_path.exists() or not meta_path.exists():
        return None
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    input_dim = int(meta.get("input_dim", 0))
    embedding_dim = int(meta.get("embedding_dim", 0))
    if input_dim <= 0 or embedding_dim <= 0:
        return None
    model = RerankerMLP(input_dim=input_dim, hidden_dim=int(meta.get("hidden_dim", 64)))
    payload = torch.load(model_path, map_location="cpu")
    model.load_state_dict(payload.get("state_dict", {}))
    model.eval()
    return RerankerBundle(model=model, input_dim=input_dim, embedding_dim=embedding_dim)
