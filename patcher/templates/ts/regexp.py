from __future__ import annotations

import re
from pathlib import Path

from patcher.types import NormalizedFinding, TemplateEdit, TemplateResult


def supports(finding: NormalizedFinding, safe_fix: str | None = None) -> bool:
    return safe_fix == "escape_regexp"


def apply(
    finding: NormalizedFinding,
    text: str,
    path: Path,
    safe_fix: str | None = None,
) -> TemplateResult:
    if safe_fix != "escape_regexp":
        return TemplateResult(applied=False, reason="missing safe_fix")
    if finding.start_line != finding.end_line:
        return TemplateResult(applied=False, reason="range not single line")

    lines = text.splitlines(keepends=True)
    if finding.start_line > len(lines):
        return TemplateResult(applied=False, reason="range out of bounds")
    line_index = finding.start_line - 1
    line = lines[line_index]

    pattern = re.compile(r"\b(new\s+)?RegExp\(\s*([A-Za-z0-9_$.]+)\s*\)")
    match = pattern.search(line)
    if not match:
        return TemplateResult(applied=False, reason="pattern not found")

    arg = match.group(2)
    replacement = f"{match.group(1) or ''}RegExp(escapeRegExp({arg}))"
    new_line = line[: match.start()] + replacement + line[match.end() :]

    start = sum(len(l) for l in lines[:line_index])
    end = start + len(line)
    helper = ""
    if "escapeRegExp" not in text:
        helper = _escape_helper_for_path(path)
    return TemplateResult(
        applied=True,
        edits=[TemplateEdit(start=start, end=end, new_text=new_line)],
        add_helpers=[helper] if helper else [],
    )


def _escape_helper_for_path(path: Path) -> str:
    is_ts = path.suffix in {".ts", ".tsx"}
    if is_ts:
        return (
            "function escapeRegExp(s: string) {\n"
            '  return s.replace(/[.*+?^${}()|[\\\\]\\\\]/g, "\\\\$&");\n'
            "}"
        )
    return (
        "function escapeRegExp(s) {\n"
        '  return s.replace(/[.*+?^${}()|[\\\\]\\\\]/g, "\\\\$&");\n'
        "}"
    )
