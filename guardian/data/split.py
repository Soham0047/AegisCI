from __future__ import annotations

from hashlib import sha256
from typing import Any


def parse_split(split: str) -> tuple[float, float, float]:
    parts = [p.strip() for p in split.split(",") if p.strip()]
    if len(parts) != 3:
        raise ValueError("Split must have three comma-separated values, e.g. 0.8,0.1,0.1")
    values = [float(p) for p in parts]
    total = sum(values)
    if total <= 0:
        raise ValueError("Split ratios must be positive")
    if abs(total - 1.0) > 0.01:
        values = [v / total for v in values]
    return values[0], values[1], values[2]


def split_for_id(sample_id: str, seed: int, split: tuple[float, float, float]) -> str:
    train_ratio, val_ratio, _ = split
    raw = f"{seed}:{sample_id}".encode()
    digest = sha256(raw).digest()
    value = int.from_bytes(digest[:8], "big") / 2**64
    if value < train_ratio:
        return "train"
    if value < train_ratio + val_ratio:
        return "val"
    return "test"


def split_samples(
    samples: list[dict[str, Any]], seed: int, split: tuple[float, float, float]
) -> dict[str, list[dict[str, Any]]]:
    buckets: dict[str, list[dict[str, Any]]] = {"train": [], "val": [], "test": []}
    for sample in samples:
        sample_id = sample["sample_id"]
        bucket = split_for_id(sample_id, seed, split)
        buckets[bucket].append(sample)
    return buckets
