import torch

from ml.graphs.common import EdgeType
from ml.graphs.python_graph import build_python_graphs


def test_python_graph_deterministic_and_edges():
    code = """
def sample(x):
    if x > 0:
        y = x + 1
    else:
        y = x - 1
    for i in range(3):
        y += i
    try:
        z = 1 / x
    except ZeroDivisionError:
        z = 0
    return y + z
"""
    graphs_a = build_python_graphs(code, max_nodes=256, max_edges=512)
    graphs_b = build_python_graphs(code, max_nodes=256, max_edges=512)
    assert graphs_a and graphs_b
    graph_a = graphs_a[0]
    graph_b = graphs_b[0]
    assert graph_a.node_type_ids.numel() > 0
    assert graph_a.edge_index.numel() > 0
    assert EdgeType.SEQ_NEXT.value in graph_a.edge_type_ids.tolist()
    assert torch.equal(graph_a.node_type_ids, graph_b.node_type_ids)
    assert torch.equal(graph_a.ident_hash_ids, graph_b.ident_hash_ids)
    assert torch.equal(graph_a.edge_index, graph_b.edge_index)
    assert torch.equal(graph_a.edge_type_ids, graph_b.edge_type_ids)
