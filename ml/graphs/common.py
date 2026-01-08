from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

import torch

NODE_TYPE_BUCKETS = 1024
IDENT_BUCKETS = 65536
LITERAL_FLAG_NAMES = ("is_string", "is_number", "is_bool", "is_null", "is_bytes")


class EdgeType(IntEnum):
    SYNTAX_PARENT = 0
    SYNTAX_CHILD = 1
    SEQ_NEXT = 2
    CONTROL_TRUE = 3
    CONTROL_FALSE = 4
    LOOP_BACK = 5
    EXCEPT_EDGE = 6


@dataclass
class GraphData:
    node_type_ids: torch.LongTensor
    ident_hash_ids: torch.LongTensor
    literal_flags: torch.FloatTensor
    edge_index: torch.LongTensor
    edge_type_ids: torch.LongTensor
    node_depth: torch.LongTensor | None = None
    span_line: torch.LongTensor | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


def stable_hash(text: str) -> int:
    digest = hashlib.sha1(text.encode("utf-8")).hexdigest()
    return int(digest, 16)


def hash_bucket(text: str, buckets: int) -> int:
    return stable_hash(text) % buckets


def node_type_id(node_type: str) -> int:
    return hash_bucket(node_type, NODE_TYPE_BUCKETS) + 1


def ident_hash_id(identifier: str | None) -> int:
    if not identifier:
        return 0
    return hash_bucket(identifier, IDENT_BUCKETS) + 1


def init_literal_flags() -> list[float]:
    return [0.0 for _ in LITERAL_FLAG_NAMES]


def to_tensor_list(values: list[list[int]] | list[list[float]], dtype: torch.dtype) -> torch.Tensor:
    if not values:
        return torch.zeros((0, 0), dtype=dtype)
    return torch.tensor(values, dtype=dtype)
