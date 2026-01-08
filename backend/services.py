from collections.abc import Iterable
from typing import Any

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.models import Finding, Report
from backend.schemas import ReportIn


def _counts_from_rows(rows: Iterable[tuple[str, int]]) -> dict[str, int]:
    counts = {"bandit": 0, "semgrep": 0}
    for source, count in rows:
        counts[source] = count
    counts["total"] = counts["bandit"] + counts["semgrep"]
    return counts


def get_report_counts_by_id(db: Session, report_ids: list[int]) -> dict[int, dict[str, int]]:
    if not report_ids:
        return {}
    rows = (
        db.query(Finding.report_id, Finding.source, func.count(Finding.id))
        .filter(Finding.report_id.in_(report_ids))
        .group_by(Finding.report_id, Finding.source)
        .all()
    )
    counts: dict[int, dict[str, int]] = {}
    for report_id, source, count in rows:
        counts.setdefault(report_id, {"bandit": 0, "semgrep": 0})
        counts[report_id][source] = count
    for report_id, per_source in counts.items():
        per_source["total"] = per_source["bandit"] + per_source["semgrep"]
    return counts


def parse_findings(report_json: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    findings: list[dict[str, Any]] = []

    bandit_results = (report_json.get("bandit") or {}).get("results") or []
    for result in bandit_results:
        message = (result.get("issue_text") or result.get("issue_name") or "").strip()
        findings.append(
            {
                "source": "bandit",
                "severity": result.get("issue_severity") or "UNKNOWN",
                "confidence": result.get("issue_confidence"),
                "rule_id": result.get("test_id") or "unknown",
                "file": result.get("filename") or "unknown",
                "line": result.get("line_number"),
                "message": message or (result.get("test_id") or "bandit finding"),
                "raw_json": result,
            }
        )

    semgrep_results = (report_json.get("semgrep") or {}).get("results") or []
    for result in semgrep_results:
        extra = result.get("extra") or {}
        message = (extra.get("message") or result.get("check_id") or "").strip()
        findings.append(
            {
                "source": "semgrep",
                "severity": extra.get("severity") or "INFO",
                "confidence": extra.get("confidence"),
                "rule_id": result.get("check_id") or "unknown",
                "file": result.get("path") or "unknown",
                "line": (result.get("start") or {}).get("line"),
                "message": message or (result.get("check_id") or "semgrep finding"),
                "raw_json": result,
            }
        )

    counts = {
        "bandit": len(bandit_results),
        "semgrep": len(semgrep_results),
        "total": len(bandit_results) + len(semgrep_results),
    }
    return findings, counts


def upsert_report_and_findings(
    db: Session, payload: ReportIn
) -> tuple[Report, bool, dict[str, int]]:
    existing = (
        db.query(Report)
        .filter(
            Report.repo == payload.repo,
            Report.pr_number == payload.pr_number,
            Report.commit_sha == payload.commit_sha,
        )
        .first()
    )
    if existing:
        rows = (
            db.query(Finding.source, func.count(Finding.id))
            .filter(Finding.report_id == existing.id)
            .group_by(Finding.source)
            .all()
        )
        row_tuples = [(row[0], row[1]) for row in rows]
        return existing, False, _counts_from_rows(row_tuples)

    raw_report = {
        "repo": payload.repo,
        "pr_number": payload.pr_number,
        "commit_sha": payload.commit_sha,
        "base_ref": payload.base_ref,
        "report": payload.report,
        "tool_versions": payload.tool_versions,
    }

    report = Report(
        repo=payload.repo,
        pr_number=payload.pr_number,
        commit_sha=payload.commit_sha,
        base_ref=payload.base_ref,
        tool_versions=payload.tool_versions,
        raw_report=raw_report,
    )
    findings_data, counts = parse_findings(payload.report)

    try:
        db.add(report)
        db.flush()
        for finding_data in findings_data:
            db.add(Finding(report_id=report.id, **finding_data))
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = (
            db.query(Report)
            .filter(
                Report.repo == payload.repo,
                Report.pr_number == payload.pr_number,
                Report.commit_sha == payload.commit_sha,
            )
            .first()
        )
        if not existing:
            raise
        rows = (
            db.query(Finding.source, func.count(Finding.id))
            .filter(Finding.report_id == existing.id)
            .group_by(Finding.source)
            .all()
        )
        row_tuples = [(row[0], row[1]) for row in rows]
        return existing, False, _counts_from_rows(row_tuples)

    db.refresh(report)
    return report, True, counts
