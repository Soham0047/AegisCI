from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from backend.celery_app import celery_app, chain
from backend.db import JobStore
from backend.integrations.github import create_or_update_comment
from backend.rendering.pr_comment import render_pr_comment
from guardian.report import build_pr_report
from patcher.diff import bundle_diffs
from patcher.orchestrator import ValidationResult, run_orchestrator


@dataclass
class PRInfo:
    repo: str
    pr_number: int
    token: str | None


def start_scan_pipeline(
    report_path: str,
    repo_root: str,
    commit: str,
    pr_info: dict[str, Any],
    dry_run: bool = False,
    report_id: str | None = None,
) -> str:
    store = JobStore()
    job_id = store.create_job(report_id or "report")
    store.set_metadata(
        job_id,
        {
            "repo_root": repo_root,
            "commit": commit,
            "repo": pr_info.get("repo") or "unknown",
            "pr": _redact_pr_info(pr_info),
        },
    )
    store.append_log(job_id, "job created")

    job_dir = _job_dir(job_id)
    job_dir.mkdir(parents=True, exist_ok=True)

    payload = {
        "job_id": job_id,
        "report_id": report_id or "report",
        "report_path": report_path,
        "repo_root": repo_root,
        "commit": commit,
        "pr_info": pr_info,
        "dry_run": dry_run,
    }

    _post_pending_comment(payload)
    workflow = chain(
        ingest_report.s(payload),
        run_model_inference.s(),
        generate_patch_candidates.s(),
        validate_patches.s(),
        post_pr_update.s(),
    )
    workflow.apply_async()
    return job_id


@celery_app.task
def ingest_report(payload: dict[str, Any]) -> dict[str, Any]:
    store = JobStore()
    job_id = payload["job_id"]
    store.update_status(job_id, "running")
    store.append_log(job_id, "ingest_report started")

    report_path = Path(payload["report_path"])
    report_json = json.loads(report_path.read_text(encoding="utf-8"))

    job_dir = _job_dir(job_id)
    job_dir.mkdir(parents=True, exist_ok=True)
    (job_dir / "report.json").write_text(json.dumps(report_json, indent=2), encoding="utf-8")

    repo_root = Path(payload["repo_root"])
    report_md, unified = build_pr_report(
        base_ref=payload.get("base_ref", "unknown"),
        py_files=[],
        js_ts_files=[],
        bandit_json=report_json.get("bandit") or {},
        semgrep_json=report_json.get("semgrep") or {},
        repo_root=repo_root,
    )
    (job_dir / "report.md").write_text(report_md, encoding="utf-8")
    (job_dir / "unified_report.json").write_text(json.dumps(unified, indent=2), encoding="utf-8")

    payload["findings"] = unified.get("findings", [])
    store.append_log(job_id, f"ingest_report found {len(payload['findings'])} findings")
    return payload


@celery_app.task
def run_model_inference(payload: dict[str, Any]) -> dict[str, Any]:
    store = JobStore()
    store.append_log(payload["job_id"], "run_model_inference stub")
    return payload


@celery_app.task
def generate_patch_candidates(payload: dict[str, Any]) -> dict[str, Any]:
    store = JobStore()
    job_id = payload["job_id"]
    store.append_log(job_id, "generate_patch_candidates started")
    repo_root = Path(payload["repo_root"])
    commit = payload["commit"]
    candidates = int(os.environ.get("PATCH_CANDIDATES", "3"))
    rag_store = _job_dir(job_id) / "rag.sqlite"

    validator = None
    if os.environ.get("PATCH_VALIDATOR_MODE") == "mock":
        validator = _mock_validator

    orchestration = run_orchestrator(
        repo_root=repo_root,
        commit=commit,
        findings=payload.get("findings", []),
        candidates=candidates,
        rag_store_path=rag_store,
        validator=validator,
    )
    payload["orchestrator"] = orchestration
    store.append_log(job_id, "generate_patch_candidates finished")
    return payload


@celery_app.task
def validate_patches(payload: dict[str, Any]) -> dict[str, Any]:
    store = JobStore()
    job_id = payload["job_id"]
    store.append_log(job_id, "validate_patches started")
    job_dir = _job_dir(job_id)
    orchestrator = payload.get("orchestrator", {})
    run_id = orchestrator.get("run_id")

    final_diffs: list[str] = []
    findings_status: list[dict[str, Any]] = []

    for item in orchestrator.get("findings", []):
        finding_id = item.get("finding_id")
        selected = item.get("selected")
        finding_dir = Path("artifacts/patch_v1") / run_id / finding_id
        status = "rejected"
        reason = "no validated patch"
        source = None
        validation_time = None
        if selected:
            selection = json.loads((finding_dir / "selection.json").read_text(encoding="utf-8"))
            selected_info = next(
                (c for c in selection.get("candidates", []) if c["candidate_id"] == selected),
                None,
            )
            if selected_info and selected_info.get("validated"):
                status = "validated"
                reason = None
                source = selected_info.get("source")
                diff_path = _diff_path_for_candidate(finding_dir, selected)
                if diff_path.exists():
                    final_diffs.append(diff_path.read_text(encoding="utf-8"))
                validation_time = _load_validation_duration(finding_dir, selected)
        findings_status.append(
            {
                "finding_id": finding_id,
                "candidate_id": selected,
                "rule_id": _safe_rule_id(payload, finding_id),
                "filepath": _safe_filepath(payload, finding_id),
                "start_line": _safe_start_line(payload, finding_id),
                "end_line": _safe_end_line(payload, finding_id),
                "status": status,
                "reason": reason,
                "source": source,
                "validation_time": validation_time,
            }
        )

    final_diff = bundle_diffs(final_diffs)
    final_path = job_dir / "final.diff"
    final_path.write_text(final_diff, encoding="utf-8")

    summary = _summarize(findings_status)
    summary["avg_validation_time"] = _avg_validation_time(findings_status)
    payload["findings_status"] = findings_status
    payload["summary"] = summary
    payload["final_diff_path"] = str(final_path)
    (job_dir / "patch_summary.json").write_text(
        json.dumps(
            {"summary": summary, "findings": findings_status, "run_id": run_id},
            indent=2,
        ),
        encoding="utf-8",
    )
    job_meta = store.get_job(job_id) or {}
    metadata = job_meta.get("metadata", {})
    metadata.update({"summary": summary, "run_id": run_id})
    store.set_metadata(job_id, metadata)
    store.append_log(job_id, f"validate_patches validated={summary['validated']}")
    store.update_status(job_id, "pending_pr")
    return payload


@celery_app.task
def post_pr_update(payload: dict[str, Any]) -> dict[str, Any]:
    store = JobStore()
    job_id = payload["job_id"]
    store.append_log(job_id, "post_pr_update started")
    pr_info = payload.get("pr_info", {})
    dry_run = payload.get("dry_run", False) or os.environ.get("GITHUB_DRY_RUN") == "1"

    diff_text = ""
    if payload.get("final_diff_path"):
        diff_text = Path(payload["final_diff_path"]).read_text(encoding="utf-8")

    comment = render_pr_comment(
        job_id=job_id,
        status="completed",
        summary=payload.get("summary", {}),
        findings=payload.get("findings_status", []),
        diff_text=diff_text,
        logs_path=str(_job_dir(job_id)),
    )
    marker = f"<!-- PATCH-COPILOT:{job_id} -->"
    result = create_or_update_comment(
        repo=pr_info.get("repo", ""),
        pr_number=int(pr_info.get("pr_number", 0)),
        marker=marker,
        body=comment,
        token=pr_info.get("token"),
        dry_run=dry_run,
    )
    if dry_run:
        out_path = _job_dir(job_id) / "github_dry_run.json"
        out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    store.update_status(job_id, "completed")
    store.append_log(job_id, "post_pr_update completed")
    return payload


def _post_pending_comment(payload: dict[str, Any]) -> None:
    job_id = payload["job_id"]
    pr_info = payload.get("pr_info", {})
    dry_run = payload.get("dry_run", False) or os.environ.get("GITHUB_DRY_RUN") == "1"
    comment = render_pr_comment(
        job_id=job_id,
        status="pending",
        summary={"total": 0, "patched": 0, "validated": 0, "rejected": 0},
        findings=[],
        diff_text=None,
        logs_path=str(_job_dir(job_id)),
    )
    marker = f"<!-- PATCH-COPILOT:{job_id} -->"
    result = create_or_update_comment(
        repo=pr_info.get("repo", ""),
        pr_number=int(pr_info.get("pr_number", 0)),
        marker=marker,
        body=comment,
        token=pr_info.get("token"),
        dry_run=dry_run,
    )
    if dry_run:
        out_path = _job_dir(job_id) / "github_pending.json"
        out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")


def _job_dir(job_id: str) -> Path:
    return Path("artifacts/jobs") / job_id


def _redact_pr_info(pr_info: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(pr_info)
    if "token" in redacted:
        redacted["token"] = "***"
    return redacted


def _mock_validator(repo_root: Path, commit: str, diff_path: Path) -> ValidationResult:
    return ValidationResult(ok=True, status="validated", report_path=None)


def _diff_path_for_candidate(finding_dir: Path, candidate_id: str) -> Path:
    if candidate_id == "det-0":
        return finding_dir / "candidate_det.diff"
    if candidate_id.startswith("llm-"):
        return finding_dir / f"candidate_{candidate_id.split('-')[-1]}.diff"
    return finding_dir / "candidate_unknown.diff"


def _summarize(findings_status: list[dict[str, Any]]) -> dict[str, int]:
    total = len(findings_status)
    validated = sum(1 for f in findings_status if f.get("status") == "validated")
    rejected = sum(1 for f in findings_status if f.get("status") == "rejected")
    patched = validated
    return {"total": total, "validated": validated, "rejected": rejected, "patched": patched}


def _load_validation_duration(finding_dir: Path, candidate_id: str) -> float | None:
    label = "det" if candidate_id == "det-0" else candidate_id.split("-")[-1]
    report_path = finding_dir / f"validation_{label}.json"
    if not report_path.exists():
        return None
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    durations = [step.get("duration") for step in report.get("steps", [])]
    durations = [float(d) for d in durations if isinstance(d, (int, float))]
    if not durations:
        return None
    return sum(durations)


def _avg_validation_time(findings_status: list[dict[str, Any]]) -> float | None:
    times = [
        item.get("validation_time")
        for item in findings_status
        if isinstance(item.get("validation_time"), (int, float))
    ]
    if not times:
        return None
    return sum(times) / len(times)


def _safe_rule_id(payload: dict[str, Any], finding_id: str) -> str:
    return _lookup_field(payload, finding_id, "rule", "rule_id")


def _safe_filepath(payload: dict[str, Any], finding_id: str) -> str:
    return _lookup_field(payload, finding_id, "location", "filepath")


def _safe_start_line(payload: dict[str, Any], finding_id: str) -> int:
    return int(_lookup_field(payload, finding_id, "location", "start_line") or 0)


def _safe_end_line(payload: dict[str, Any], finding_id: str) -> int:
    return int(_lookup_field(payload, finding_id, "location", "end_line") or 0)


def _lookup_field(payload: dict[str, Any], finding_id: str, section: str, key: str) -> Any:
    for finding in payload.get("findings", []):
        if finding.get("finding_id") == finding_id:
            return (finding.get(section) or {}).get(key)
    return ""
