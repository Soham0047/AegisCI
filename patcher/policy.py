from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from patcher.types import NormalizedFinding


@dataclass
class PatchPolicyDecision:
    allowed: bool
    reason: str
    tags: list[str] = field(default_factory=list)


@dataclass
class _Change:
    line_no: int
    text: str
    kind: str  # add | del


@dataclass
class _FileChanges:
    path: str
    hunks: int = 0
    changes: list[_Change] = field(default_factory=list)


_DEFAULT_ALLOWED = {
    "injection.xss",
    "xss",
    "innerhtml",
    "insecure-request",
    "injection.command",
    "command-injection",
    "injection.sql",
    "path.traversal",
    "ssrf",
    "unsafe.exec",
}

_DISALLOWED_ADDITION_PATTERNS = [
    re.compile(r"\bbcrypt\b", re.IGNORECASE),
    re.compile(r"\bargon2\b", re.IGNORECASE),
    re.compile(r"\bpasslib\b", re.IGNORECASE),
    re.compile(r"\bhashlib\.(md5|sha1)\b", re.IGNORECASE),
    re.compile(r"\bmd5\b", re.IGNORECASE),
    re.compile(r"\bsha1\b", re.IGNORECASE),
    re.compile(r"\beval\(", re.IGNORECASE),
    re.compile(r"\bexec\(", re.IGNORECASE),
    re.compile(r"\bos\.system\(", re.IGNORECASE),
    re.compile(r"\bsubprocess\.(run|popen)\(", re.IGNORECASE),
    re.compile(r"\bshell\s*=\s*True\b"),
]


def evaluate_llm_diff(
    diff: str,
    finding: NormalizedFinding,
    repo_root: Path,
) -> PatchPolicyDecision:
    if not diff.strip():
        return PatchPolicyDecision(False, "empty diff")

    allowed = _load_allowed_categories()
    category = (finding.category or "").lower()
    rule_id = (finding.rule_id or "").lower()
    if not _category_allowed(category, rule_id, allowed):
        return PatchPolicyDecision(False, "category not in allowlist", tags=["category"])

    files = _parse_unified_diff(diff)
    if len(files) != 1:
        return PatchPolicyDecision(False, "diff touches multiple files", tags=["files"])

    file_change = files[0]
    if _normalize_path(file_change.path) != _normalize_path(finding.filepath):
        return PatchPolicyDecision(False, "diff file does not match finding", tags=["filepath"])

    max_changed = _env_int("PATCH_LLM_MAX_CHANGED_LINES", 20)
    max_hunks = _env_int("PATCH_LLM_MAX_HUNKS", 3)
    if file_change.hunks > max_hunks:
        return PatchPolicyDecision(False, "too many hunks", tags=["hunks"])

    changed_lines = [c for c in file_change.changes if c.kind in {"add", "del"}]
    if len(changed_lines) > max_changed:
        return PatchPolicyDecision(False, "too many changed lines", tags=["lines"])

    import_limit = _env_int("PATCH_LLM_IMPORT_LIMIT", 40)
    import_end = _detect_import_region_end(repo_root / finding.filepath, import_limit)
    tolerance = _env_int("PATCH_LLM_LINE_TOLERANCE", 3)

    for change in changed_lines:
        if _is_import_line(change.text) and change.line_no <= import_end:
            continue
        if finding.start_line - tolerance <= change.line_no <= finding.end_line + tolerance:
            continue
        return PatchPolicyDecision(
            False,
            "change outside finding range",
            tags=["line_range"],
        )

    blocked = _find_disallowed_additions(changed_lines)
    if blocked:
        return PatchPolicyDecision(False, "disallowed addition detected", tags=blocked)

    return PatchPolicyDecision(True, "allowed")


def _find_disallowed_additions(changes: list[_Change]) -> list[str]:
    tags: list[str] = []
    for change in changes:
        if change.kind != "add":
            continue
        text = change.text.strip()
        if _is_comment_line(text):
            continue
        for pattern in _DISALLOWED_ADDITION_PATTERNS:
            if pattern.search(text):
                tags.append(pattern.pattern)
                break
    return tags


def _category_allowed(category: str, rule_id: str, allowed: set[str]) -> bool:
    if not allowed:
        return True
    if category in allowed or rule_id in allowed:
        return True
    for value in allowed:
        if value and (value in category or value in rule_id):
            return True
    return False


def _load_allowed_categories() -> set[str]:
    raw = os.getenv("PATCH_LLM_ALLOWED_CATEGORIES")
    if not raw:
        return set(_DEFAULT_ALLOWED)
    return {part.strip().lower() for part in raw.split(",") if part.strip()}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _parse_unified_diff(diff: str) -> list[_FileChanges]:
    files: list[_FileChanges] = []
    current: _FileChanges | None = None
    old_line = 0
    new_line = 0
    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[4:].strip()
            if path.startswith("b/"):
                path = path[2:]
            if path == "/dev/null":
                continue
            current = _FileChanges(path=path)
            files.append(current)
            continue
        if line.startswith("@@") and current is not None:
            old_line, new_line = _parse_hunk_header(line)
            current.hunks += 1
            continue
        if current is None:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            current.changes.append(_Change(line_no=new_line, text=line[1:], kind="add"))
            new_line += 1
        elif line.startswith("-") and not line.startswith("---"):
            current.changes.append(_Change(line_no=old_line, text=line[1:], kind="del"))
            old_line += 1
        else:
            old_line += 1
            new_line += 1
    return files


def _parse_hunk_header(header: str) -> tuple[int, int]:
    match = re.search(r"-([0-9]+)(?:,([0-9]+))? \+([0-9]+)(?:,([0-9]+))?", header)
    if not match:
        return 0, 0
    old_start = int(match.group(1))
    new_start = int(match.group(3))
    return old_start, new_start


def _detect_import_region_end(path: Path, max_lines: int) -> int:
    if not path.exists():
        return 0
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    end = 0
    for idx, line in enumerate(lines[:max_lines], start=1):
        stripped = line.strip()
        if not stripped or _is_comment_line(stripped):
            end = idx
            continue
        if _is_import_line(stripped):
            end = idx
            continue
        break
    return end


def _is_import_line(text: str) -> bool:
    stripped = text.lstrip()
    if stripped.startswith(("import ", "from ")):
        return True
    if stripped.startswith("import{") or stripped.startswith("import{"):
        return True
    if "require(" in stripped and stripped.startswith(("const ", "let ", "var ")):
        return True
    return False


def _is_comment_line(text: str) -> bool:
    stripped = text.lstrip()
    return stripped.startswith(("#", "//", "/*", "*"))


def _normalize_path(path: str) -> str:
    return path.replace("\\", "/").strip()


def decision_to_json(decision: PatchPolicyDecision) -> dict[str, Any]:
    return {"allowed": decision.allowed, "reason": decision.reason, "tags": decision.tags}
