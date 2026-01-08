from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Candidate:
    candidate_id: str
    diff: str
    source: str
    diff_ok: bool
    validated: bool
    validation_status: str


@dataclass
class RankedCandidate:
    candidate: Candidate
    lines_changed: int
    files_changed: int
    hunks: int


def rank_candidates(candidates: list[Candidate]) -> tuple[Candidate | None, dict]:
    validated = [c for c in candidates if c.diff_ok and c.validated]
    ranked = [_score_candidate(c) for c in validated]
    ranked.sort(
        key=lambda r: (
            0 if r.candidate.source == "deterministic" else 1,
            r.lines_changed,
            r.files_changed,
            r.hunks,
            r.candidate.candidate_id,
        )
    )
    selected = ranked[0].candidate if ranked else None
    report = {
        "selected": selected.candidate_id if selected else None,
        "candidates": [
            {
                "candidate_id": r.candidate.candidate_id,
                "source": r.candidate.source,
                "lines_changed": r.lines_changed,
                "files_changed": r.files_changed,
                "hunks": r.hunks,
                "validated": r.candidate.validated,
                "diff_ok": r.candidate.diff_ok,
                "validation_status": r.candidate.validation_status,
            }
            for r in ranked
        ],
    }
    return selected, report


def _score_candidate(candidate: Candidate) -> RankedCandidate:
    files_changed = 0
    hunks = 0
    lines_changed = 0
    for line in candidate.diff.splitlines():
        if line.startswith("+++ b/"):
            files_changed += 1
        elif line.startswith("@@"):
            hunks += 1
        elif line.startswith("+") and not line.startswith("+++"):
            lines_changed += 1
        elif line.startswith("-") and not line.startswith("---"):
            lines_changed += 1
    return RankedCandidate(
        candidate=candidate,
        lines_changed=lines_changed,
        files_changed=max(files_changed, 1) if candidate.diff else 0,
        hunks=hunks,
    )
