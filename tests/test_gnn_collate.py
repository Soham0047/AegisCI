from dataclasses import dataclass

import torch

from ml.data.gnn_collate import collate_graph_samples
from ml.graphs.common import GraphData


@dataclass
class DummySample:
    graph: GraphData
    risk_label: int
    category: str


def test_gnn_collate_offsets_edges():
    graph_a = GraphData(
        node_type_ids=torch.tensor([1, 2], dtype=torch.long),
        ident_hash_ids=torch.tensor([0, 1], dtype=torch.long),
        literal_flags=torch.zeros((2, 5), dtype=torch.float32),
        edge_index=torch.tensor([[0], [1]], dtype=torch.long),
        edge_type_ids=torch.tensor([0], dtype=torch.long),
        node_depth=torch.tensor([0, 1], dtype=torch.long),
        span_line=torch.tensor([1, 2], dtype=torch.long),
        metadata={},
    )
    graph_b = GraphData(
        node_type_ids=torch.tensor([3], dtype=torch.long),
        ident_hash_ids=torch.tensor([2], dtype=torch.long),
        literal_flags=torch.zeros((1, 5), dtype=torch.float32),
        edge_index=torch.zeros((2, 0), dtype=torch.long),
        edge_type_ids=torch.zeros((0,), dtype=torch.long),
        node_depth=torch.tensor([0], dtype=torch.long),
        span_line=torch.tensor([1], dtype=torch.long),
        metadata={},
    )
    samples = [
        DummySample(graph=graph_a, risk_label=1, category="a"),
        DummySample(graph=graph_b, risk_label=0, category="b"),
    ]
    batch = collate_graph_samples(samples, {"a": 0, "b": 1})
    assert batch.node_type_ids.shape[0] == 3
    assert batch.edge_index.shape[1] == 1
    assert batch.edge_index[0, 0].item() == 0
    assert batch.edge_index[1, 0].item() == 1
    assert batch.batch_index.tolist() == [0, 0, 1]
