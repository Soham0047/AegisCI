from __future__ import annotations

import difflib


def make_unified_diff(path: str, old_text: str, new_text: str) -> str:
    if old_text == new_text:
        return ""

    old_lines = old_text.splitlines(keepends=True)
    new_lines = new_text.splitlines(keepends=True)

    diff_lines = difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
        lineterm="\n",
    )
    return "".join(diff_lines)


def _diff_path(diff: str) -> str:
    for line in diff.splitlines():
        if line.startswith("--- a/"):
            return line[6:].strip()
    return ""


def bundle_diffs(diffs: list[str]) -> str:
    ordered = sorted((d for d in diffs if d.strip()), key=_diff_path)
    return "\n".join(ordered).rstrip() + ("\n" if ordered else "")
