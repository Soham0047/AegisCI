from __future__ import annotations

import hashlib
import json
import math
import os
import re
from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path

import torch

from rag.dl.dataset import Vocab
from rag.dl.models import DualEncoder, EncoderConfig, batch_lengths


def tokenize(text: str) -> list[str]:
    return re.findall(r"[A-Za-z_][A-Za-z0-9_]+", text.lower())


def embed_text(text: str, dim: int = 256) -> list[float]:
    model = _load_dl_model()
    if model:
        return _dl_embed(text, model)
    return _hash_embed(text, dim)


def _hash_embed(text: str, dim: int) -> list[float]:
    vec = [0.0] * dim
    for token in tokenize(text):
        digest = hashlib.sha1(token.encode("utf-8")).hexdigest()
        bucket = int(digest[:8], 16) % dim
        vec[bucket] += 1.0
    norm = math.sqrt(sum(v * v for v in vec))
    if norm == 0:
        return vec
    return [v / norm for v in vec]


def _dl_embed(text: str, bundle: _DLBundle) -> list[float]:
    tokens = bundle.vocab.encode(text, bundle.config.max_len)
    tensor = torch.tensor([tokens], dtype=torch.long)
    lengths = batch_lengths(tensor)
    vector = bundle.model.encode(tensor, lengths).squeeze(0)
    return vector.detach().cpu().tolist()


class _DLBundle:
    def __init__(self, model: DualEncoder, vocab: Vocab, config: EncoderConfig) -> None:
        self.model = model
        self.vocab = vocab
        self.config = config


@lru_cache(maxsize=1)
def _load_dl_model() -> _DLBundle | None:
    artifacts = Path(os.environ.get("DL_ARTIFACTS_DIR", "artifacts/dl"))
    model_path = artifacts / "embeddings_model.pt"
    vocab_path = artifacts / "vocab.json"
    if not model_path.exists() or not vocab_path.exists():
        return None
    payload = torch.load(model_path, map_location="cpu")
    config_data = payload.get("config")
    if not config_data:
        return None
    config = EncoderConfig(**config_data)
    vocab_json = Vocab.from_json(_load_json(vocab_path))
    model = DualEncoder(config)
    model.load_state_dict(payload.get("state_dict", {}))
    model.eval()
    return _DLBundle(model=model, vocab=vocab_json, config=config)


def cosine_similarity(a: Iterable[float], b: Iterable[float]) -> float:
    dot = 0.0
    norm_a = 0.0
    norm_b = 0.0
    for x, y in zip(a, b):
        dot += x * y
        norm_a += x * x
        norm_b += y * y
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (math.sqrt(norm_a) * math.sqrt(norm_b))


def _load_json(path: Path) -> dict[str, int]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
