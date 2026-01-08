from __future__ import annotations

from collections.abc import Sequence

import torch

from ml.models.gnn import GraphBatch


def collate_graph_samples(samples: Sequence, category_to_id: dict[str, int]) -> GraphBatch:
    node_type_ids = []
    ident_hash_ids = []
    literal_flags = []
    node_depth = []
    edge_index = []
    batch_index = []
    risk_labels = []
    category_labels = []

    node_offset = 0
    for graph_id, sample in enumerate(samples):
        graph = sample.graph
        num_nodes = graph.node_type_ids.numel()
        node_type_ids.append(graph.node_type_ids)
        ident_hash_ids.append(graph.ident_hash_ids)
        literal_flags.append(graph.literal_flags)
        depth = graph.node_depth if graph.node_depth is not None else torch.zeros(num_nodes)
        node_depth.append(depth)

        if graph.edge_index.numel() > 0:
            edge_index.append(graph.edge_index + node_offset)

        batch_index.append(torch.full((num_nodes,), graph_id, dtype=torch.long))

        risk_labels.append(sample.risk_label)
        category_labels.append(category_to_id.get(sample.category, -1))

        node_offset += num_nodes

    return GraphBatch(
        node_type_ids=torch.cat(node_type_ids, dim=0),
        ident_hash_ids=torch.cat(ident_hash_ids, dim=0),
        literal_flags=torch.cat(literal_flags, dim=0),
        node_depth=torch.cat(node_depth, dim=0),
        edge_index=(
            torch.cat(edge_index, dim=1) if edge_index else torch.zeros((2, 0), dtype=torch.long)
        ),
        batch_index=torch.cat(batch_index, dim=0),
        risk_labels=torch.tensor(risk_labels, dtype=torch.float32),
        category_labels=torch.tensor(category_labels, dtype=torch.long),
    )
