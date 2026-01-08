from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class NormalizedFinding:
    finding_id: str
    rule_id: str
    category: str
    filepath: str
    start_line: int
    end_line: int
    start_col: int | None
    end_col: int | None
    source: str
    raw: dict[str, Any] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class TemplateEdit:
    start: int
    end: int
    new_text: str


@dataclass
class TemplateResult:
    applied: bool
    edits: list[TemplateEdit] = field(default_factory=list)
    add_imports: set[str] = field(default_factory=set)
    add_helpers: list[str] = field(default_factory=list)
    reason: str | None = None


@dataclass
class PatchResult:
    finding_id: str
    applied: bool
    reason_if_not: str | None
    changed_files: list[str]
    hunks_count: int


@dataclass
class PatchBundle:
    diffs_by_file: dict[str, str]
    combined_diff: str
    results: list[PatchResult]
    patched_files: dict[str, str]
