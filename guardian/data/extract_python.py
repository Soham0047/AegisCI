from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import Any

from guardian.data.schema import make_sample_id

LOGGER = logging.getLogger(__name__)
MAX_SNIPPET_LINES = 400


def _compute_cyclomatic_complexity(node: ast.AST) -> int:
    complexity = 1
    for child in ast.walk(node):
        if isinstance(
            child,
            (
                ast.If,
                ast.For,
                ast.AsyncFor,
                ast.While,
                ast.Try,
                ast.With,
                ast.AsyncWith,
                ast.IfExp,
                ast.ExceptHandler,
            ),
        ):
            complexity += 1
        elif isinstance(child, ast.BoolOp):
            complexity += 1
        elif isinstance(child, ast.comprehension):
            complexity += 1
    return complexity


def _context_lines(
    lines: list[str], start_line: int, end_line: int, context: int
) -> tuple[str, str]:
    before = lines[max(0, start_line - 1 - context) : start_line - 1]
    after = lines[end_line : end_line + context]
    return "\n".join(before), "\n".join(after)


def extract_python_samples(
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
        tree = ast.parse(source)
    except SyntaxError as exc:
        LOGGER.warning("Failed to parse %s: %s", file_path, exc)
        return []

    samples: list[dict[str, Any]] = []
    rel_path = file_path.relative_to(repo_root).as_posix()
    file_ext = file_path.suffix

    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        start_line = getattr(node, "lineno", None)
        end_line = getattr(node, "end_lineno", None)
        if not start_line or not end_line:
            continue
        if end_line - start_line + 1 > max_snippet_lines:
            continue

        snippet_lines = lines[start_line - 1 : end_line]
        code_snippet = "\n".join(snippet_lines)
        context_before, context_after = _context_lines(lines, start_line, end_line, context_lines)
        start_col = getattr(node, "col_offset", 0) or 0
        end_col = getattr(node, "end_col_offset", 0) or 0

        cyclomatic = None
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            cyclomatic = _compute_cyclomatic_complexity(node)

        sample: dict[str, Any] = {
            "sample_id": make_sample_id("python", repo_id, commit, rel_path, start_line, end_line),
            "language": "python",
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
                "cyclomatic_complexity": cyclomatic,
                "dependencies": {"python": [], "npm": []},
                "tool_versions": tool_versions,
            },
        }
        samples.append(sample)

    return samples
