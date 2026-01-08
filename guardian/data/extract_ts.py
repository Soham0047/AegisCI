from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from guardian.data.schema import make_sample_id

LOGGER = logging.getLogger(__name__)
MAX_SNIPPET_LINES = 400


def _get_parser_for_ext(ext: str):
    try:
        from tree_sitter_languages import get_parser
    except ImportError as exc:  # pragma: no cover - handled in tests by dependency
        raise RuntimeError("tree_sitter_languages is required for TS/JS extraction") from exc

    if ext in {".ts"}:
        return get_parser("typescript")
    if ext in {".tsx", ".jsx"}:
        return get_parser("tsx")
    return get_parser("javascript")


def _node_span(node) -> tuple[int, int, int, int]:
    start_line = node.start_point[0] + 1
    end_line = node.end_point[0] + 1
    start_col = node.start_point[1]
    end_col = node.end_point[1]
    return start_line, end_line, start_col, end_col


def _context_lines(
    lines: list[str], start_line: int, end_line: int, context: int
) -> tuple[str, str]:
    before = lines[max(0, start_line - 1 - context) : start_line - 1]
    after = lines[end_line : end_line + context]
    return "\n".join(before), "\n".join(after)


def _is_named_arrow_function(node) -> bool:
    parent = node.parent
    if not parent:
        return False
    if parent.type == "variable_declarator":
        name = parent.child_by_field_name("name")
        return bool(name and name.type in {"identifier", "property_identifier"})
    if parent.type == "assignment_expression":
        left = parent.child_by_field_name("left")
        return bool(left and left.type in {"identifier", "property_identifier"})
    return False


def _should_capture(node) -> bool:
    if node.type in {"function_declaration", "class_declaration", "method_definition"}:
        return True
    if node.type == "arrow_function":
        return _is_named_arrow_function(node)
    return False


def extract_ts_samples(
    file_path: Path,
    repo_root: Path,
    repo_id: str,
    commit: str,
    context_lines: int = 10,
    max_snippet_lines: int = MAX_SNIPPET_LINES,
    tool_versions: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    tool_versions = tool_versions or {}
    try:
        source = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        LOGGER.warning("Failed to read %s: %s", file_path, exc)
        return []

    lines = source.splitlines()
    n_lines = len(lines)
    if n_lines == 0:
        return []

    try:
        parser = _get_parser_for_ext(file_path.suffix)
    except RuntimeError as exc:
        LOGGER.warning("%s", exc)
        return []

    tree = parser.parse(source.encode("utf-8"))
    if tree.root_node.has_error:
        LOGGER.warning("Parse errors in %s", file_path)

    rel_path = file_path.relative_to(repo_root).as_posix()
    file_ext = file_path.suffix
    samples: list[dict[str, Any]] = []

    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if _should_capture(node):
            start_line, end_line, start_col, end_col = _node_span(node)
            if end_line - start_line + 1 > max_snippet_lines:
                continue
            snippet_lines = lines[start_line - 1 : end_line]
            code_snippet = "\n".join(snippet_lines)
            context_before, context_after = _context_lines(
                lines, start_line, end_line, context_lines
            )
            sample: dict[str, Any] = {
                "sample_id": make_sample_id("ts", repo_id, commit, rel_path, start_line, end_line),
                "language": "ts",
                "repo": repo_id,
                "commit": commit,
                "filepath": rel_path,
                "code_snippet": code_snippet,
                "function_span": {
                    "start_line": start_line,
                    "end_line": end_line,
                    "start_col": start_col,
                    "end_col": end_col,
                },
                "context_before": context_before,
                "context_after": context_after,
                "weak_labels": [],
                "gold_labels": None,
                "metadata": {
                    "file_ext": file_ext,
                    "n_lines": n_lines,
                    "cyclomatic_complexity": None,
                    "dependencies": {"python": [], "npm": []},
                    "tool_versions": tool_versions,
                },
            }
            samples.append(sample)

        stack.extend(reversed(node.children))

    return samples
