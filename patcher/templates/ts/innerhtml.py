from __future__ import annotations

import re
from pathlib import Path

from patcher.types import NormalizedFinding, TemplateEdit, TemplateResult


def supports(finding: NormalizedFinding, safe_fix: str | None = None) -> bool:
    return safe_fix == "untrusted_to_innerhtml"


def apply(
    finding: NormalizedFinding,
    text: str,
    path: Path,
    safe_fix: str | None = None,
) -> TemplateResult:
    if safe_fix != "untrusted_to_innerhtml":
        return TemplateResult(applied=False, reason="missing safe_fix")
    if finding.start_line != finding.end_line:
        return TemplateResult(applied=False, reason="range not single line")

    lines = text.splitlines(keepends=True)
    if finding.start_line > len(lines):
        return TemplateResult(applied=False, reason="range out of bounds")
    line_index = finding.start_line - 1
    line = lines[line_index]
    if ".innerHTML" not in line or "=" not in line:
        return TemplateResult(applied=False, reason="pattern not found")
    if re.search(r"\.innerHTML\s*=", line) is None:
        return TemplateResult(applied=False, reason="pattern not found")

    new_line = line.replace(".innerHTML", ".textContent", 1)
    if new_line == line:
        return TemplateResult(applied=False, reason="no change")

    start = sum(len(l) for l in lines[:line_index])
    end = start + len(line)
    return TemplateResult(
        applied=True,
        edits=[TemplateEdit(start=start, end=end, new_text=new_line)],
    )
