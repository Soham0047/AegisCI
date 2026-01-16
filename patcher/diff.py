from __future__ import annotations

import difflib
import re


def make_unified_diff(path: str, old_text: str, new_text: str) -> str:
    if old_text == new_text:
        return ""

    old_lines = old_text.splitlines(keepends=True)
    new_lines = new_text.splitlines(keepends=True)

    header = f"diff --git a/{path} b/{path}\n"
    diff_lines = difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
        lineterm="\n",
    )
    return header + "".join(diff_lines)


def _diff_path(diff: str) -> str:
    for line in diff.splitlines():
        if line.startswith("--- a/"):
            return line[6:].strip()
    return ""


def bundle_diffs(diffs: list[str]) -> str:
    ordered = sorted((d for d in diffs if d.strip()), key=_diff_path)
    parts: list[str] = []
    for diff in ordered:
        if diff and not diff.endswith("\n"):
            diff += "\n"
        parts.append(diff)
    return "".join(parts)


_HUNK_RE = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? "
    r"\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@"
)


def normalize_unified_diff(diff: str) -> str:
    """
    Normalize unified diff hunk counts based on actual hunk lines.

    This helps recover LLM-generated diffs with incorrect @@ counts.
    """
    if not diff.strip():
        return diff

    lines = diff.splitlines()
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        match = _HUNK_RE.match(line)
        if match:
            old_start = match.group("old_start")
            new_start = match.group("new_start")
            old_count = 0
            new_count = 0
            j = i + 1
            while j < len(lines):
                next_line = lines[j]
                if _HUNK_RE.match(next_line):
                    break
                if (
                    next_line.startswith("diff --git")
                    or next_line.startswith("--- ")
                    or next_line.startswith("+++ ")
                ):
                    break
                if next_line.startswith("\\"):
                    j += 1
                    continue
                if next_line.startswith("+") and not next_line.startswith("+++"):
                    new_count += 1
                elif next_line.startswith("-") and not next_line.startswith("---"):
                    old_count += 1
                else:
                    old_count += 1
                    new_count += 1
                j += 1

            out.append(f"@@ -{old_start},{old_count} +{new_start},{new_count} @@")
            out.extend(lines[i + 1 : j])
            i = j
            continue

        out.append(line)
        i += 1

    normalized = "\n".join(out)
    if normalized and not normalized.endswith("\n"):
        normalized += "\n"
    return normalized
