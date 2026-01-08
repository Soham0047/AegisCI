from __future__ import annotations

"""
Normalized finding schema used by patcher:
- finding_id: str
- rule.rule_id or rule_id: str
- rule.category or category: str
- location.filepath or filepath: str
- location.start_line/end_line (1-based)
- location.start_col/end_col (optional)
- raw/extra may include safe_fix hints
"""

import json
from pathlib import Path
from typing import Any, Iterable

from patcher.diff import bundle_diffs, make_unified_diff
from patcher.templates.python import get_python_templates
from patcher.templates.ts import get_ts_templates
from patcher.types import NormalizedFinding, PatchBundle, PatchResult, TemplateEdit


def load_findings(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "findings" in data:
        return data["findings"]
    if isinstance(data, list):
        return data
    return []


def _get_safe_fix(finding: NormalizedFinding) -> str | None:
    candidates = []
    if finding.extra:
        candidates.append(finding.extra.get("safe_fix"))
    if finding.raw:
        candidates.append(finding.raw.get("safe_fix"))
        if isinstance(finding.raw.get("extra"), dict):
            candidates.append(finding.raw.get("extra", {}).get("safe_fix"))
        if isinstance(finding.raw.get("tool"), dict):
            tool_extra = finding.raw.get("tool", {}).get("extra", {})
            if isinstance(tool_extra, dict):
                candidates.append(tool_extra.get("safe_fix"))
    for value in candidates:
        if value:
            return str(value)
    return None


def normalize_findings(items: Iterable[dict[str, Any]]) -> list[NormalizedFinding]:
    normalized: list[NormalizedFinding] = []
    for item in items:
        rule = item.get("rule") or {}
        location = item.get("location") or {}
        finding_id = str(item.get("finding_id") or "")
        filepath = str(location.get("filepath") or item.get("filepath") or "")
        if not finding_id or not filepath:
            continue
        start_line = int(location.get("start_line") or item.get("start_line") or 0)
        end_line = int(location.get("end_line") or item.get("end_line") or start_line)
        if not start_line or not end_line:
            continue
        normalized.append(
            NormalizedFinding(
                finding_id=finding_id,
                rule_id=str(rule.get("rule_id") or item.get("rule_id") or ""),
                category=str(rule.get("category") or item.get("category") or ""),
                filepath=filepath,
                start_line=start_line,
                end_line=end_line,
                start_col=location.get("start_col"),
                end_col=location.get("end_col"),
                source=str(item.get("source") or ""),
                raw=item.get("raw") or {},
                extra=item.get("extra") or {},
            )
        )
    return normalized


def _apply_edits(text: str, edits: list[TemplateEdit]) -> str:
    if not edits:
        return text
    ordered = sorted(edits, key=lambda e: e.start, reverse=True)
    for edit in ordered:
        text = text[: edit.start] + edit.new_text + text[edit.end :]
    return text


def _ensure_imports(text: str, imports: set[str]) -> str:
    if not imports:
        return text
    lines = text.splitlines(keepends=True)
    existing = {line.strip() for line in lines if line.strip().startswith(("import ", "from "))}
    needed = []
    for name in sorted(imports):
        if any(line == f"import {name}" or line.startswith(f"from {name} ") for line in existing):
            continue
        needed.append(f"import {name}")
    if not needed:
        return text
    insert_at = 0
    for idx, line in enumerate(lines):
        if line.startswith("import ") or line.startswith("from "):
            insert_at = idx + 1
    insert_block = [line + "\n" for line in needed]
    return "".join(lines[:insert_at] + insert_block + lines[insert_at:])


def _ensure_helpers(text: str, helpers: list[str]) -> str:
    if not helpers:
        return text
    filtered: list[str] = []
    for helper in helpers:
        first_line = helper.splitlines()[0].strip() if helper else ""
        if not first_line:
            continue
        if first_line in text:
            continue
        filtered.append(helper)
    if not filtered:
        return text
    lines = text.splitlines(keepends=True)
    insert_at = 0
    for idx, line in enumerate(lines):
        if line.lstrip().startswith("import "):
            insert_at = idx + 1
    block = []
    for helper in filtered:
        block.append(helper.rstrip() + "\n")
        block.append("\n")
    return "".join(lines[:insert_at] + block + lines[insert_at:])


def generate_patches(
    repo_root: Path,
    findings: list[dict[str, Any]] | list[NormalizedFinding],
    commit_hash: str | None = None,
) -> PatchBundle:
    if findings and isinstance(findings[0], NormalizedFinding):
        normalized = list(findings)  # type: ignore[list-item]
    else:
        normalized = normalize_findings(findings)  # type: ignore[arg-type]

    results: list[PatchResult] = []
    diffs_by_file: dict[str, str] = {}
    patched_files: dict[str, str] = {}

    files: dict[str, list[NormalizedFinding]] = {}
    for finding in normalized:
        files.setdefault(finding.filepath, []).append(finding)

    for filepath in sorted(files):
        path = repo_root / filepath
        if not path.exists():
            for finding in files[filepath]:
                results.append(
                    PatchResult(
                        finding_id=finding.finding_id,
                        applied=False,
                        reason_if_not="file not found",
                        changed_files=[],
                        hunks_count=0,
                    )
                )
            continue

        original = path.read_text(encoding="utf-8")
        updated = original
        edits: list[TemplateEdit] = []
        add_imports: set[str] = set()
        add_helpers: list[str] = []

        file_findings = sorted(
            files[filepath],
            key=lambda f: (f.start_line, f.finding_id),
            reverse=True,
        )

        for finding in file_findings:
            language = _language_for_path(filepath)
            if language == "python":
                templates = get_python_templates()
            else:
                templates = get_ts_templates()

            applied = False
            reason = "no matching template"
            for template in templates:
                if not template.supports(finding, safe_fix=_get_safe_fix(finding)):
                    continue
                result = template.apply(finding, updated, path, safe_fix=_get_safe_fix(finding))
                if result.applied:
                    if _has_overlap(edits, result.edits):
                        applied = False
                        reason = "overlapping edit"
                        break
                    edits.extend(result.edits)
                    add_imports |= result.add_imports
                    add_helpers.extend(result.add_helpers)
                    applied = True
                    reason = None
                    break
                reason = result.reason or reason

            results.append(
                PatchResult(
                    finding_id=finding.finding_id,
                    applied=applied,
                    reason_if_not=None if applied else reason,
                    changed_files=[filepath] if applied else [],
                    hunks_count=0,
                )
            )

        if edits or add_imports or add_helpers:
            updated = _apply_edits(updated, edits)
            updated = _ensure_imports(updated, add_imports)
            updated = _ensure_helpers(updated, add_helpers)
            if updated != original:
                diff = make_unified_diff(filepath, original, updated)
                diffs_by_file[filepath] = diff
                patched_files[filepath] = updated

    combined = bundle_diffs(list(diffs_by_file.values()))
    for result in results:
        if result.applied and result.changed_files:
            result.hunks_count = combined.count("\n@@ ") if combined else 0

    return PatchBundle(
        diffs_by_file=diffs_by_file,
        combined_diff=combined,
        results=results,
        patched_files=patched_files,
    )


def _language_for_path(path: str) -> str:
    suffix = Path(path).suffix.lower()
    if suffix == ".py":
        return "python"
    if suffix in {".ts", ".tsx", ".js", ".jsx"}:
        return "ts"
    return "unknown"


def _has_overlap(existing: list[TemplateEdit], incoming: list[TemplateEdit]) -> bool:
    for inc in incoming:
        for cur in existing:
            if inc.start < cur.end and cur.start < inc.end:
                return True
    return False
