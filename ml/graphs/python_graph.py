from __future__ import annotations

import ast
import logging
from collections.abc import Iterable

import torch

from ml.graphs.common import (
    EdgeType,
    GraphData,
    ident_hash_id,
    init_literal_flags,
    node_type_id,
)

LOGGER = logging.getLogger(__name__)
DEFAULT_MAX_NODES = 2048
DEFAULT_MAX_EDGES = 8192


def _identifier_for_node(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.arg):
        return node.arg
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return node.name
    return None


def _literal_flags(node: ast.AST) -> list[float]:
    flags = init_literal_flags()
    if isinstance(node, ast.Constant):
        value = node.value
        if isinstance(value, str):
            flags[0] = 1.0
        elif isinstance(value, (int, float, complex)):
            flags[1] = 1.0
        elif isinstance(value, bool):
            flags[2] = 1.0
        elif value is None:
            flags[3] = 1.0
        elif isinstance(value, bytes):
            flags[4] = 1.0
    return flags


def _node_span_line(node: ast.AST) -> int:
    return getattr(node, "lineno", 0) or 0


def _iter_child_lists(node: ast.AST) -> Iterable[list[ast.AST]]:
    for field in ("body", "orelse", "handlers", "finalbody"):
        value = getattr(node, field, None)
        if isinstance(value, list):
            yield value


def _add_seq_edges(
    node_ids: dict[int, int],
    stmt_list: list[ast.AST],
    edges: list[tuple[int, int, EdgeType]],
) -> None:
    for first, second in zip(stmt_list, stmt_list[1:]):
        first_id = node_ids.get(id(first))
        second_id = node_ids.get(id(second))
        if first_id is None or second_id is None:
            continue
        edges.append((first_id, second_id, EdgeType.SEQ_NEXT))


def _add_control_edges(
    node_ids: dict[int, int],
    node: ast.AST,
    edges: list[tuple[int, int, EdgeType]],
) -> None:
    node_id = node_ids.get(id(node))
    if node_id is None:
        return
    if isinstance(node, ast.If):
        if node.body:
            first = node_ids.get(id(node.body[0]))
            if first is not None:
                edges.append((node_id, first, EdgeType.CONTROL_TRUE))
        if node.orelse:
            first = node_ids.get(id(node.orelse[0]))
            if first is not None:
                edges.append((node_id, first, EdgeType.CONTROL_FALSE))
    if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
        if node.body:
            first = node_ids.get(id(node.body[0]))
            last = node_ids.get(id(node.body[-1]))
            if first is not None:
                edges.append((node_id, first, EdgeType.CONTROL_TRUE))
            if last is not None:
                edges.append((last, node_id, EdgeType.LOOP_BACK))
        if node.orelse:
            first = node_ids.get(id(node.orelse[0]))
            if first is not None:
                edges.append((node_id, first, EdgeType.CONTROL_FALSE))
    if isinstance(node, ast.Try):
        if node.handlers:
            first_handler = node_ids.get(id(node.handlers[0]))
            if first_handler is not None:
                edges.append((node_id, first_handler, EdgeType.EXCEPT_EDGE))


def _build_graph_for_root(
    root: ast.AST,
    max_nodes: int,
    max_edges: int,
) -> GraphData:
    node_ids: dict[int, int] = {}
    node_types: list[int] = []
    ident_hashes: list[int] = []
    literal_flags: list[list[float]] = []
    node_depths: list[int] = []
    span_lines: list[int] = []
    edges: list[tuple[int, int, EdgeType]] = []
    truncated = False

    stack: list[tuple[ast.AST, int, int | None]] = [(root, 0, None)]
    while stack:
        node, depth, parent_id = stack.pop()
        if len(node_types) >= max_nodes:
            truncated = True
            continue
        node_id = len(node_types)
        node_ids[id(node)] = node_id
        node_types.append(node_type_id(type(node).__name__))
        ident_hashes.append(ident_hash_id(_identifier_for_node(node)))
        literal_flags.append(_literal_flags(node))
        node_depths.append(depth)
        span_lines.append(_node_span_line(node))

        if parent_id is not None:
            edges.append((parent_id, node_id, EdgeType.SYNTAX_PARENT))
            edges.append((node_id, parent_id, EdgeType.SYNTAX_CHILD))

        children = list(ast.iter_child_nodes(node))
        for child in reversed(children):
            stack.append((child, depth + 1, node_id))

    for node in ast.walk(root):
        for stmt_list in _iter_child_lists(node):
            _add_seq_edges(node_ids, stmt_list, edges)
        _add_control_edges(node_ids, node, edges)

    if len(edges) > max_edges:
        edges = edges[:max_edges]
        truncated = True

    edge_index = torch.tensor([[src for src, _, _ in edges], [dst for _, dst, _ in edges]])
    edge_type_ids = torch.tensor([edge.value for _, _, edge in edges], dtype=torch.long)

    return GraphData(
        node_type_ids=torch.tensor(node_types, dtype=torch.long),
        ident_hash_ids=torch.tensor(ident_hashes, dtype=torch.long),
        literal_flags=torch.tensor(literal_flags, dtype=torch.float32),
        edge_index=edge_index.long(),
        edge_type_ids=edge_type_ids,
        node_depth=torch.tensor(node_depths, dtype=torch.long),
        span_line=torch.tensor(span_lines, dtype=torch.long),
        metadata={"language": "python", "truncated": truncated, "parse_errors": False},
    )


def build_python_graphs(
    code: str,
    max_nodes: int = DEFAULT_MAX_NODES,
    max_edges: int = DEFAULT_MAX_EDGES,
) -> list[GraphData]:
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        LOGGER.warning("Python parse error: %s", exc)
        return []

    functions = [
        node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    if not functions:
        return [_build_graph_for_root(tree, max_nodes=max_nodes, max_edges=max_edges)]
    graphs: list[GraphData] = []
    for func in functions:
        graphs.append(_build_graph_for_root(func, max_nodes=max_nodes, max_edges=max_edges))
    return graphs
