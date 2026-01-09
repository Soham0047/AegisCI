from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

FEATURE_NAMES = [
    "lines_changed",
    "files_changed",
    "hunks",
    "diff_chars",
    "source_is_deterministic",
    "validated",
    "lint_errors",
    "test_failures",
]


@dataclass
class FeatureVector:
    values: list[float]
    names: list[str] = field(default_factory=lambda: list(FEATURE_NAMES))


class _CandidateLike(Protocol):
    candidate_id: str
    diff: str
    source: str
    diff_ok: bool
    validated: bool
    validation_status: str
    metadata: dict[str, Any]


def extract_features(candidate: _CandidateLike) -> FeatureVector:
    lines_changed, files_changed, hunks = _diff_stats(candidate.diff)
    diff_chars = float(len(candidate.diff))
    source_is_det = 1.0 if candidate.source == "deterministic" else 0.0
    validated = 1.0 if candidate.validated else 0.0
    lint_errors, test_failures = _lint_and_test_failures(candidate)
    return FeatureVector(
        values=[
            float(lines_changed),
            float(files_changed),
            float(hunks),
            diff_chars,
            source_is_det,
            validated,
            float(lint_errors),
            float(test_failures),
        ]
    )


def _diff_stats(diff: str) -> tuple[int, int, int]:
    files_changed = 0
    hunks = 0
    lines_changed = 0
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            files_changed += 1
        elif line.startswith("@@"):
            hunks += 1
        elif line.startswith("+") and not line.startswith("+++"):
            lines_changed += 1
        elif line.startswith("-") and not line.startswith("---"):
            lines_changed += 1
    return lines_changed, max(files_changed, 1) if diff else 0, hunks


def _lint_and_test_failures(candidate: _CandidateLike) -> tuple[int, int]:
    report_path = None
    if candidate.metadata:
        report_path = candidate.metadata.get("validation_report")
    if not report_path:
        return 0, 0
    report = _load_json(Path(report_path))
    run_id = report.get("run_id")
    if not run_id:
        return 0, 0
    base = Path("artifacts/validation") / run_id
    lint_errors = _count_errors(base / "ruff.out") + _count_errors(base / "eslint.out")
    test_failures = _count_errors(base / "pytest.err") + _count_errors(base / "jest.err")
    return lint_errors, test_failures


def _count_errors(path: Path) -> int:
    if not path.exists():
        return 0
    text = path.read_text(encoding="utf-8", errors="ignore")
    return len(re.findall(r"\berror\b", text, flags=re.IGNORECASE))


def _load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
