from __future__ import annotations

import ast
import re
from pathlib import Path

from patcher.types import NormalizedFinding, TemplateEdit, TemplateResult

SUPPORTED_RULES = {"B602"}


def supports(finding: NormalizedFinding, safe_fix: str | None = None) -> bool:
    return finding.rule_id in SUPPORTED_RULES or finding.category in SUPPORTED_RULES


def apply(
    finding: NormalizedFinding,
    text: str,
    path: Path,
    safe_fix: str | None = None,
) -> TemplateResult:
    if not finding.start_line or not finding.end_line:
        return TemplateResult(applied=False, reason="missing range")
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return TemplateResult(applied=False, reason="parse failed")

    candidates: list[ast.Call] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and hasattr(node, "lineno"):
            if node.lineno >= finding.start_line and node.end_lineno <= finding.end_line:
                candidates.append(node)

    for call in candidates:
        func = call.func
        if not isinstance(func, ast.Attribute):
            continue
        if not isinstance(func.value, ast.Name) or func.value.id != "subprocess":
            continue
        if func.attr not in {"run", "Popen"}:
            continue
        if not call.args or not isinstance(call.args[0], (ast.List, ast.Tuple)):
            continue
        shell_kw = None
        for kw in call.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                shell_kw = kw
                break
        if not shell_kw:
            continue

        snippet = ast.get_source_segment(text, call)
        if not snippet or "shell" not in snippet:
            continue

        new_snippet = _remove_shell_true(snippet)
        if new_snippet == snippet:
            continue

        start, end = _node_span_to_offsets(text, call)
        return TemplateResult(
            applied=True,
            edits=[TemplateEdit(start=start, end=end, new_text=new_snippet)],
        )

    return TemplateResult(applied=False, reason="no matching call")


def _remove_shell_true(snippet: str) -> str:
    new = re.sub(r",\s*shell\s*=\s*True\s*", "", snippet)
    new = re.sub(r"\s*shell\s*=\s*True\s*,\s*", "", new)
    return new


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
