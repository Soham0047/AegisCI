import pytest
import torch

from ml.graphs.ts_graph import build_ts_graphs


def test_ts_graph_deterministic():
    pytest.importorskip("tree_sitter_languages")
    code = """
function sample(x) {
  if (x > 0) {
    let y = x + 1;
    return y;
  } else {
    return x - 1;
  }
}
"""
    graphs_a = build_ts_graphs(code, language="ts", max_nodes=256, max_edges=512)
    graphs_b = build_ts_graphs(code, language="ts", max_nodes=256, max_edges=512)
    assert graphs_a and graphs_b
    graph_a = graphs_a[0]
    graph_b = graphs_b[0]
    assert graph_a.node_type_ids.numel() > 0
    assert graph_a.edge_index.numel() > 0
    assert torch.equal(graph_a.node_type_ids, graph_b.node_type_ids)
    assert torch.equal(graph_a.edge_index, graph_b.edge_index)
