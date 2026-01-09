from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

import torch
from torch import nn
from torch.nn import functional as F


@dataclass
class EncoderConfig:
    vocab_size: int
    embed_dim: int
    hidden_dim: int
    max_len: int


class DualEncoder(nn.Module):
    def __init__(self, config: EncoderConfig) -> None:
        super().__init__()
        self.config = config
        self.embedding = nn.Embedding(config.vocab_size, config.embed_dim, padding_idx=0)
        self.encoder = nn.GRU(
            input_size=config.embed_dim,
            hidden_size=config.hidden_dim,
            num_layers=1,
            batch_first=True,
            bidirectional=True,
        )
        self.proj = nn.Linear(config.hidden_dim * 2, config.hidden_dim)

    def forward(self, tokens: torch.Tensor, lengths: torch.Tensor) -> torch.Tensor:
        embedded = self.embedding(tokens)
        outputs, _ = self.encoder(embedded)
        mask = (tokens != 0).unsqueeze(-1)
        masked = outputs * mask
        summed = masked.sum(dim=1)
        lengths = lengths.clamp(min=1).unsqueeze(-1)
        pooled = summed / lengths
        projected = self.proj(pooled)
        return F.normalize(projected, p=2, dim=-1)

    def encode(self, tokens: torch.Tensor, lengths: torch.Tensor) -> torch.Tensor:
        self.eval()
        with torch.no_grad():
            return self.forward(tokens, lengths)


class RerankerMLP(nn.Module):
    def __init__(self, input_dim: int, hidden_dim: int = 128) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, 1),
        )

    def forward(self, features: torch.Tensor) -> torch.Tensor:
        return self.net(features).squeeze(-1)


def build_pair_features(query_emb: torch.Tensor, doc_emb: torch.Tensor) -> torch.Tensor:
    return torch.cat(
        [
            query_emb,
            doc_emb,
            torch.abs(query_emb - doc_emb),
            query_emb * doc_emb,
        ],
        dim=-1,
    )


def batch_lengths(tokens: torch.Tensor) -> torch.Tensor:
    lengths = (tokens != 0).sum(dim=1)
    return lengths


def to_device(tensors: Iterable[torch.Tensor], device: torch.device) -> list[torch.Tensor]:
    return [tensor.to(device) for tensor in tensors]
