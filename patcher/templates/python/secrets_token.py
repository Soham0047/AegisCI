from __future__ import annotations

import ast
from pathlib import Path

from patcher.types import NormalizedFinding, TemplateEdit, TemplateResult


def supports(finding: NormalizedFinding, safe_fix: str | None = None) -> bool:
    return safe_fix == "secrets_token"


def apply(
    finding: NormalizedFinding,
    text: str,
    path: Path,
    safe_fix: str | None = None,
) -> TemplateResult:
    if safe_fix != "secrets_token":
        return TemplateResult(applied=False, reason="missing safe_fix")
    if not finding.start_line or not finding.end_line:
        return TemplateResult(applied=False, reason="missing range")
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return TemplateResult(applied=False, reason="parse failed")

    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    calls: list[ast.Call] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and hasattr(node, "lineno"):
            if node.lineno >= finding.start_line and node.end_lineno <= finding.end_line:
                calls.append(node)

    for call in calls:
        func = call.func
        if not isinstance(func, ast.Attribute):
            continue
        if not isinstance(func.value, ast.Name) or func.value.id != "random":
            continue
        if func.attr == "choice":
            new_snippet = ast.get_source_segment(text, call)
            if not new_snippet:
                continue
            new_snippet = new_snippet.replace("random.choice", "secrets.choice", 1)
            start, end = _node_span_to_offsets(text, call)
            return TemplateResult(
                applied=True,
                edits=[TemplateEdit(start=start, end=end, new_text=new_snippet)],
                add_imports={"secrets"},
            )
        if func.attr == "random":
            parent = parents.get(call)
            if not _is_safe_random_parent(parent, call):
                continue
            start, end = _node_span_to_offsets(text, call)
            return TemplateResult(
                applied=True,
                edits=[TemplateEdit(start=start, end=end, new_text="secrets.token_urlsafe(32)")],
                add_imports={"secrets"},
            )

    return TemplateResult(applied=False, reason="no matching random call")


def _is_safe_random_parent(parent: ast.AST | None, node: ast.Call) -> bool:
    if parent is None:
        return False
    if isinstance(parent, ast.Call):
        if isinstance(parent.func, ast.Name) and parent.func.id == "str":
            return len(parent.args) == 1 and parent.args[0] is node
    if isinstance(parent, ast.FormattedValue):
        return True
    return False


def _node_span_to_offsets(text: str, node: ast.AST) -> tuple[int, int]:
    lines = text.splitlines(keepends=True)
    offsets = [0]
    running = 0
    for line in lines:
        running += len(line)
        offsets.append(running)
    start = offsets[node.lineno - 1] + node.col_offset
    end = offsets[node.end_lineno - 1] + node.end_col_offset
    return start, end
