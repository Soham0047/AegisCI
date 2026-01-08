from __future__ import annotations

import logging
from typing import Any

import torch

from ml.graphs.common import EdgeType, GraphData, ident_hash_id, init_literal_flags, node_type_id

LOGGER = logging.getLogger(__name__)
DEFAULT_MAX_NODES = 2048
DEFAULT_MAX_EDGES = 8192


def _get_parser(lang: str):
    try:
        from tree_sitter_languages import get_parser
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("tree_sitter_languages is required for TS/JS graphs") from exc
    if lang in {"ts", "typescript"}:
        return get_parser("typescript")
    if lang in {"tsx", "jsx"}:
        return get_parser("tsx")
    return get_parser("javascript")


def _node_text(source: bytes, node) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")


def _identifier_for_node(source: bytes, node) -> str | None:
    if node.type in {
        "identifier",
        "property_identifier",
        "shorthand_property_identifier_pattern",
        "type_identifier",
    }:
        return _node_text(source, node)
    return None


def _literal_flags(node) -> list[float]:
    flags = init_literal_flags()
    if node.type in {"string", "string_fragment", "template_string"}:
        flags[0] = 1.0
    elif node.type == "number":
        flags[1] = 1.0
    elif node.type in {"true", "false"}:
        flags[2] = 1.0
    elif node.type in {"null", "undefined"}:
        flags[3] = 1.0
    return flags


def _node_span_line(node) -> int:
    return node.start_point[0] + 1 if node.start_point else 0


def _is_statement(node) -> bool:
    return node.type.endswith("statement") or node.type in {
        "lexical_declaration",
        "variable_declaration",
        "expression_statement",
        "return_statement",
        "function_declaration",
        "class_declaration",
        "import_statement",
    }


def _add_seq_edges(children, node_ids, edges) -> None:
    stmts = [child for child in children if _is_statement(child)]
    for first, second in zip(stmts, stmts[1:]):
        first_id = node_ids.get(id(first))
        second_id = node_ids.get(id(second))
        if first_id is None or second_id is None:
            continue
        edges.append((first_id, second_id, EdgeType.SEQ_NEXT))


def _add_control_edges(node, node_ids, edges) -> None:
    node_id = node_ids.get(id(node))
    if node_id is None:
        return
    if node.type == "if_statement":
        consequence = node.child_by_field_name("consequence")
        alternative = node.child_by_field_name("alternative")
        if consequence:
            target = node_ids.get(id(consequence))
            if target is not None:
                edges.append((node_id, target, EdgeType.CONTROL_TRUE))
        if alternative:
            target = node_ids.get(id(alternative))
            if target is not None:
                edges.append((node_id, target, EdgeType.CONTROL_FALSE))
    if node.type in {
        "for_statement",
        "for_in_statement",
        "for_of_statement",
        "while_statement",
        "do_statement",
    }:
        body = node.child_by_field_name("body")
        if body:
            target = node_ids.get(id(body))
            if target is not None:
                edges.append((node_id, target, EdgeType.CONTROL_TRUE))
                edges.append((target, node_id, EdgeType.LOOP_BACK))
    if node.type == "try_statement":
        handler = node.child_by_field_name("handler")
        if handler:
            target = node_ids.get(id(handler))
            if target is not None:
                edges.append((node_id, target, EdgeType.EXCEPT_EDGE))


def _build_graph(
    code: str,
    language: str,
    max_nodes: int,
    max_edges: int,
) -> GraphData | None:
    try:
        parser = _get_parser(language)
    except RuntimeError as exc:
        LOGGER.warning("%s", exc)
        return None

    source = code.encode("utf-8")
    tree = parser.parse(source)
    root = tree.root_node
    parse_errors = root.has_error

    node_ids: dict[int, int] = {}
    node_types: list[int] = []
    ident_hashes: list[int] = []
    literal_flags: list[list[float]] = []
    node_depths: list[int] = []
    span_lines: list[int] = []
    edges: list[tuple[int, int, EdgeType]] = []
    truncated = False

    nodes_in_order: list[Any] = []
    stack: list[tuple[Any, int, int | None]] = [(root, 0, None)]
    while stack:
        node, depth, parent_id = stack.pop()
        if len(node_types) >= max_nodes:
            truncated = True
            continue
        nodes_in_order.append(node)
        node_id = len(node_types)
        node_ids[id(node)] = node_id
        node_types.append(node_type_id(node.type))
        ident_hashes.append(ident_hash_id(_identifier_for_node(source, node)))
        literal_flags.append(_literal_flags(node))
        node_depths.append(depth)
        span_lines.append(_node_span_line(node))

        if parent_id is not None:
            edges.append((parent_id, node_id, EdgeType.SYNTAX_PARENT))
            edges.append((node_id, parent_id, EdgeType.SYNTAX_CHILD))

        children = list(node.children)
        for child in reversed(children):
            stack.append((child, depth + 1, node_id))

    for node in nodes_in_order:
        _add_seq_edges(node.children, node_ids, edges)
        _add_control_edges(node, node_ids, edges)

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
        metadata={
            "language": "ts",
            "truncated": truncated,
            "parse_errors": parse_errors,
        },
    )


def build_ts_graphs(
    code: str,
    language: str = "ts",
    max_nodes: int = DEFAULT_MAX_NODES,
    max_edges: int = DEFAULT_MAX_EDGES,
) -> list[GraphData]:
    graph = _build_graph(code, language=language, max_nodes=max_nodes, max_edges=max_edges)
    return [graph] if graph else []
