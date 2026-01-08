from __future__ import annotations

import ast
from pathlib import Path

from patcher.types import NormalizedFinding, TemplateEdit, TemplateResult


def supports(finding: NormalizedFinding, safe_fix: str | None = None) -> bool:
    return safe_fix == "compare_digest"


def apply(
    finding: NormalizedFinding,
    text: str,
    path: Path,
    safe_fix: str | None = None,
) -> TemplateResult:
    if safe_fix != "compare_digest":
        return TemplateResult(applied=False, reason="missing safe_fix")
    if not finding.start_line or not finding.end_line:
        return TemplateResult(applied=False, reason="missing range")
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return TemplateResult(applied=False, reason="parse failed")

    comparisons: list[ast.Compare] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare) and hasattr(node, "lineno"):
            if node.lineno >= finding.start_line and node.end_lineno <= finding.end_line:
                comparisons.append(node)

    for node in comparisons:
        if len(node.ops) != 1 or len(node.comparators) != 1:
            continue
        if not isinstance(node.ops[0], ast.Eq):
            continue
        left_src = ast.get_source_segment(text, node.left)
        right_src = ast.get_source_segment(text, node.comparators[0])
        if not left_src or not right_src:
            continue
        new_expr = f"hmac.compare_digest({left_src}, {right_src})"
        start, end = _node_span_to_offsets(text, node)
        return TemplateResult(
            applied=True,
            edits=[TemplateEdit(start=start, end=end, new_text=new_expr)],
            add_imports={"hmac"},
        )

    return TemplateResult(applied=False, reason="no matching compare")


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
