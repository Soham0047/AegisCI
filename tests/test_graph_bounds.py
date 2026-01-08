from ml.graphs.python_graph import build_python_graphs


def test_graph_bounds_truncation():
    lines = ["def f():"]
    lines.extend([f"    x{i} = {i}" for i in range(200)])
    code = "\n".join(lines)
    graphs = build_python_graphs(code, max_nodes=10, max_edges=20)
    assert graphs
    graph = graphs[0]
    assert graph.metadata.get("truncated") is True
    assert graph.node_type_ids.numel() <= 10
    assert graph.edge_type_ids.numel() <= 20
