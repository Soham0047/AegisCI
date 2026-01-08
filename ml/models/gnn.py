from __future__ import annotations

from dataclasses import dataclass

import torch
from torch import nn

from ml.graphs.common import IDENT_BUCKETS, NODE_TYPE_BUCKETS


@dataclass
class GraphBatch:
    node_type_ids: torch.Tensor
    ident_hash_ids: torch.Tensor
    literal_flags: torch.Tensor
    node_depth: torch.Tensor
    edge_index: torch.Tensor
    batch_index: torch.Tensor
    risk_labels: torch.Tensor
    category_labels: torch.Tensor


def global_mean_pool(node_embeddings: torch.Tensor, batch_index: torch.Tensor) -> torch.Tensor:
    num_graphs = int(batch_index.max().item()) + 1 if batch_index.numel() else 0
    if num_graphs == 0:
        return torch.zeros((0, node_embeddings.size(1)), device=node_embeddings.device)
    pooled = torch.zeros((num_graphs, node_embeddings.size(1)), device=node_embeddings.device)
    pooled.index_add_(0, batch_index, node_embeddings)
    counts = torch.zeros(num_graphs, device=node_embeddings.device)
    counts.index_add_(0, batch_index, torch.ones_like(batch_index, dtype=torch.float32))
    counts = counts.clamp(min=1.0).unsqueeze(-1)
    return pooled / counts


class GraphSageLayer(nn.Module):
    def __init__(self, in_dim: int, out_dim: int) -> None:
        super().__init__()
        self.self_lin = nn.Linear(in_dim, out_dim)
        self.neigh_lin = nn.Linear(in_dim, out_dim)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        if edge_index.numel() == 0:
            return torch.relu(self.self_lin(x))
        src, dst = edge_index
        agg = torch.zeros_like(x)
        agg.index_add_(0, dst, x[src])
        deg = torch.zeros(x.size(0), device=x.device)
        deg.index_add_(0, dst, torch.ones_like(dst, dtype=torch.float32))
        deg = deg.clamp(min=1.0).unsqueeze(-1)
        neigh = agg / deg
        return torch.relu(self.self_lin(x) + self.neigh_lin(neigh))


class GraphClassifier(nn.Module):
    def __init__(
        self,
        num_categories: int,
        node_emb_dim: int = 64,
        ident_emb_dim: int = 32,
        hidden_dim: int = 128,
        num_layers: int = 2,
        dropout: float = 0.1,
    ) -> None:
        super().__init__()
        self.node_type_emb = nn.Embedding(NODE_TYPE_BUCKETS + 2, node_emb_dim)
        self.ident_emb = nn.Embedding(IDENT_BUCKETS + 2, ident_emb_dim)
        self.dropout = nn.Dropout(dropout)
        in_dim = node_emb_dim + ident_emb_dim + 6

        layers = []
        for idx in range(num_layers):
            layers.append(GraphSageLayer(in_dim if idx == 0 else hidden_dim, hidden_dim))
        self.layers = nn.ModuleList(layers)

        self.risk_head = nn.Linear(hidden_dim, 1)
        self.category_head = nn.Linear(hidden_dim, num_categories)

    def encode(self, batch: GraphBatch) -> torch.Tensor:
        node_type = self.node_type_emb(batch.node_type_ids)
        ident = self.ident_emb(batch.ident_hash_ids)
        depth = batch.node_depth.float().unsqueeze(-1)
        max_depth = depth.max().clamp(min=1.0)
        depth = depth / max_depth
        literal_flags = batch.literal_flags
        x = torch.cat([node_type, ident, literal_flags, depth], dim=-1)
        x = self.dropout(x)
        for layer in self.layers:
            x = layer(x, batch.edge_index)
        graph_emb = global_mean_pool(x, batch.batch_index)
        return self.dropout(graph_emb)

    def forward(self, batch: GraphBatch) -> tuple[torch.Tensor, torch.Tensor]:
        graph_emb = self.encode(batch)
        risk_logit = self.risk_head(graph_emb).squeeze(-1)
        category_logits = self.category_head(graph_emb)
        return risk_logit, category_logits
