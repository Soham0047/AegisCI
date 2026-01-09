from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from backend.db import GatewayEventStore, JobStore, PatchOutcomeStore
from guardian.findings import normalize_severity, redact_secrets, severity_rank


class DashboardService:
    def __init__(
        self,
        jobs_db_path: str | None = None,
        artifacts_root: Path | None = None,
        gateway_events_db_path: str | None = None,
        outcomes_db_path: str | None = None,
    ) -> None:
        self.job_store = JobStore(jobs_db_path)
        self.events_store = GatewayEventStore(gateway_events_db_path)
        self.outcome_store = PatchOutcomeStore(outcomes_db_path)
        self.artifacts_root = artifacts_root or Path("artifacts/jobs")

    def list_reports(
        self,
        repo: str | None,
        commit: str | None,
        severity: str | None,
        since: str | None,
        until: str | None,
        limit: int,
    ) -> list[dict[str, Any]]:
        jobs = self.job_store.list_jobs(
            limit=limit * 2,
            repo=repo,
            commit=commit,
            since=since,
            until=until,
        )
        results = []
        for job in jobs:
            report = self._load_unified_report(job["id"])
            if not report:
                continue
            findings = report.get("findings", [])
            filtered = self._filter_findings_by_severity(findings, severity)
            if severity and not filtered:
                continue
            counts = self._counts_by_severity(filtered)
            results.append(
                {
                    "report_id": job["id"],
                    "job_id": job["id"],
                    "repo": job["metadata"].get("repo", "unknown"),
                    "commit": job["metadata"].get("commit", ""),
                    "created_at": job.get("started_at") or job.get("finished_at"),
                    "findings_count": counts["total"],
                    "high_critical": counts["high"] + counts["critical"],
                    "severity_counts": counts,
                }
            )
        results.sort(key=lambda item: _sort_ts(item.get("created_at")), reverse=True)
        return results[:limit]

    def get_report_detail(
        self,
        report_id: str,
        severity: str | None,
    ) -> dict[str, Any] | None:
        job = self.job_store.get_job(report_id)
        if not job:
            return None
        report = self._load_unified_report(report_id)
        if not report:
            return None
        findings = report.get("findings", [])
        filtered = self._filter_findings_by_severity(findings, severity)
        counts = self._counts_by_severity(filtered)
        grouped = self._group_findings(filtered)
        return {
            "report_id": report_id,
            "job_id": report_id,
            "repo": job["metadata"].get("repo", "unknown"),
            "commit": job["metadata"].get("commit", ""),
            "created_at": job.get("started_at") or job.get("finished_at"),
            "summary": counts,
            "files": grouped,
        }

    def list_patches(
        self,
        repo: str | None,
        commit: str | None,
        status: str | None,
        since: str | None,
        until: str | None,
        limit: int,
    ) -> list[dict[str, Any]]:
        jobs = self.job_store.list_jobs(
            limit=limit * 2,
            repo=repo,
            commit=commit,
            status=status,
            since=since,
            until=until,
        )
        results = []
        for job in jobs:
            summary = self._load_patch_summary(job["id"])
            if not summary:
                continue
            counts = summary.get("summary", {})
            total = counts.get("total") or 0
            validated = counts.get("validated") or 0
            success_rate = (validated / total) if total else 0.0
            outcomes = self.outcome_store.list_outcomes(job_id=job["id"], limit=200)
            accepted = sum(1 for item in outcomes if item.get("action") == "accepted")
            acceptance_rate = (accepted / len(outcomes)) if outcomes else 0.0
            results.append(
                {
                    "job_id": job["id"],
                    "repo": job["metadata"].get("repo", "unknown"),
                    "commit": job["metadata"].get("commit", ""),
                    "status": job.get("status"),
                    "validated_count": validated,
                    "rejected_count": counts.get("rejected") or 0,
                    "avg_validation_time": counts.get("avg_validation_time"),
                    "success_rate": round(success_rate, 3),
                    "acceptance_rate": round(acceptance_rate, 3),
                    "created_at": job.get("started_at") or job.get("finished_at"),
                }
            )
        results.sort(key=lambda item: _sort_ts(item.get("created_at")), reverse=True)
        return results[:limit]

    def get_patch_detail(self, job_id: str) -> dict[str, Any] | None:
        job = self.job_store.get_job(job_id)
        if not job:
            return None
        summary = self._load_patch_summary(job_id)
        if not summary:
            return None
        outcomes = self.outcome_store.list_outcomes(job_id=job_id, limit=200)
        diff = self._load_diff(job_id)
        return {
            "job_id": job_id,
            "repo": job["metadata"].get("repo", "unknown"),
            "commit": job["metadata"].get("commit", ""),
            "status": job.get("status"),
            "summary": summary.get("summary", {}),
            "findings": summary.get("findings", []),
            "diff": diff,
            "run_id": summary.get("run_id"),
            "outcomes": outcomes,
        }

    def list_gateway_events(
        self,
        decision: str | None,
        repo: str | None,
        since: str | None,
        until: str | None,
        limit: int,
    ) -> list[dict[str, Any]]:
        return self.events_store.list_events(
            limit=limit,
            decision=decision,
            repo=repo,
            since=since,
            until=until,
        )

    def gateway_summary(
        self,
        repo: str | None,
        since: str | None,
        until: str | None,
    ) -> dict[str, Any]:
        events = self.events_store.list_events(
            limit=500,
            repo=repo,
            since=since,
            until=until,
        )
        blocked = [e for e in events if e.get("decision") in {"deny", "require_approval"}]
        reasons = Counter(e.get("reason", "unknown") for e in events)
        tools = Counter(e.get("tool", "unknown") for e in events)
        return {
            "total": len(events),
            "blocked": len(blocked),
            "top_reasons": reasons.most_common(5),
            "top_tools": tools.most_common(5),
        }

    def _load_unified_report(self, job_id: str) -> dict[str, Any] | None:
        path = self.artifacts_root / job_id / "unified_report.json"
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None

    def _load_patch_summary(self, job_id: str) -> dict[str, Any] | None:
        path = self.artifacts_root / job_id / "patch_summary.json"
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None

    def _load_diff(self, job_id: str, max_lines: int = 400) -> str:
        path = self.artifacts_root / job_id / "final.diff"
        if not path.exists():
            return ""
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        if len(lines) <= max_lines:
            return text
        return "\n".join(lines[:max_lines]) + "\n... (truncated)"

    def _filter_findings_by_severity(
        self, findings: list[dict[str, Any]], severity: str | None
    ) -> list[dict[str, Any]]:
        if not severity:
            return findings
        threshold = severity_rank(severity)
        return [
            finding
            for finding in findings
            if severity_rank(normalize_severity(finding.get("severity"))) >= threshold
        ]

    def _counts_by_severity(self, findings: list[dict[str, Any]]) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        for finding in findings:
            severity = normalize_severity(finding.get("severity"))
            counts[severity] = counts.get(severity, 0) + 1
            counts["total"] += 1
        return counts

    def _group_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        grouped: dict[str, dict[str, Any]] = {}
        for finding in findings:
            location = finding.get("location") or {}
            filepath = location.get("filepath") or "unknown"
            bucket = grouped.setdefault(
                filepath,
                {
                    "filepath": filepath,
                    "severity_counts": Counter(),
                    "category_counts": Counter(),
                    "rule_counts": Counter(),
                    "findings": [],
                },
            )
            severity = normalize_severity(finding.get("severity"))
            bucket["severity_counts"][severity] += 1
            rule = finding.get("rule") or {}
            bucket["category_counts"][rule.get("category", "unknown")] += 1
            bucket["rule_counts"][rule.get("rule_id", "unknown")] += 1
            bucket["findings"].append(self._simplify_finding(finding))

        results = []
        for filepath, payload in grouped.items():
            payload["findings"] = sorted(
                payload["findings"],
                key=lambda item: (
                    -severity_rank(item["severity"]),
                    item.get("start_line", 0),
                ),
            )[:20]
            payload["severity_counts"] = dict(payload["severity_counts"])
            payload["category_counts"] = dict(payload["category_counts"])
            payload["rule_counts"] = dict(payload["rule_counts"])
            results.append(payload)
        results.sort(key=lambda item: item["filepath"])
        return results

    def _simplify_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        location = finding.get("location") or {}
        rule = finding.get("rule") or {}
        evidence = finding.get("evidence") or {}
        excerpt = evidence.get("excerpt") or ""
        excerpt = redact_secrets(excerpt)
        if len(excerpt) > 400:
            excerpt = excerpt[:380].rstrip() + "...(truncated)"
        return {
            "finding_id": finding.get("finding_id"),
            "severity": normalize_severity(finding.get("severity")),
            "source": finding.get("source"),
            "rule_id": rule.get("rule_id"),
            "category": rule.get("category"),
            "start_line": location.get("start_line"),
            "end_line": location.get("end_line"),
            "confidence": finding.get("confidence"),
            "message": (finding.get("why") or {}).get("tool_message"),
            "excerpt": excerpt,
        }


def default_since(days: int = 7) -> str:
    return (datetime.now(UTC) - timedelta(days=days)).isoformat()


def _sort_ts(value: str | None) -> float:
    if not value:
        return 0.0
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return 0.0
