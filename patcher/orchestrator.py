from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from hashlib import sha1
from pathlib import Path
from typing import Any, Callable

from patcher import generate_patches
from patcher.llm_client import PatchGenerationResult, generate_patch, redact_text
from patcher.ranker import Candidate, rank_candidates
from patcher.types import NormalizedFinding
from rag.indexer import build_index
from rag.retriever import RAGRetriever


@dataclass
class ValidationResult:
    ok: bool
    status: str
    report_path: str | None


ValidatorFn = Callable[[Path, str, Path], ValidationResult]


def run_orchestrator(
    repo_root: Path,
    commit: str,
    findings: list[dict[str, Any]] | list[NormalizedFinding],
    candidates: int = 3,
    rag_store_path: Path = Path("rag/store/rag.sqlite"),
    validator: ValidatorFn | None = None,
) -> dict[str, Any]:
    run_id = _run_id(commit, findings)
    out_dir = Path("artifacts/patch_v1") / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    if not rag_store_path.exists():
        kb_paths = [Path("rag/kb")]
        build_index(kb_paths, rag_store_path)

    retriever = RAGRetriever(rag_store_path)
    results: dict[str, Any] = {"run_id": run_id, "findings": []}

    if findings and isinstance(findings[0], NormalizedFinding):
        norm_findings = list(findings)  # type: ignore[list-item]
    else:
        from patcher.patcher import normalize_findings

        norm_findings = normalize_findings(findings)  # type: ignore[arg-type]

    for finding in norm_findings:
        finding_dir = out_dir / finding.finding_id
        finding_dir.mkdir(parents=True, exist_ok=True)
        context = _build_context(repo_root, finding)
        citations = _retrieve_citations(retriever, finding)
        context["citations"] = citations
        _write_json(finding_dir / "context.json", _redact_context(context))
        _write_json(finding_dir / "citations.json", citations)
        prompt_text = _build_prompt_text(context, citations)
        (finding_dir / "prompt.txt").write_text(redact_text(prompt_text), encoding="utf-8")

        candidates_list: list[Candidate] = []
        det_result = _deterministic_candidate(repo_root, commit, finding, validator, finding_dir)
        if det_result:
            candidates_list.append(det_result)

        for idx in range(candidates):
            context["candidate_id"] = f"llm-{idx}"
            result = generate_patch(context)
            diff_path = finding_dir / f"candidate_{idx}.diff"
            raw_path = finding_dir / f"candidate_{idx}_raw.txt"
            raw_path.write_text(redact_text(result.raw), encoding="utf-8")
            if result.ok and result.diff:
                diff_path.write_text(result.diff, encoding="utf-8")
                validation = _validate(
                    validator, repo_root, commit, diff_path, finding_dir, str(idx)
                )
                candidates_list.append(
                    Candidate(
                        candidate_id=f"llm-{idx}",
                        diff=result.diff,
                        source="llm",
                        diff_ok=True,
                        validated=validation.ok,
                        validation_status=validation.status,
                    )
                )
            else:
                candidates_list.append(
                    Candidate(
                        candidate_id=f"llm-{idx}",
                        diff="",
                        source="llm",
                        diff_ok=False,
                        validated=False,
                        validation_status=result.error or "diff invalid",
                    )
                )

        selected, ranking_report = rank_candidates(candidates_list)
        _write_json(finding_dir / "selection.json", ranking_report)
        results["findings"].append(
            {
                "finding_id": finding.finding_id,
                "selected": selected.candidate_id if selected else None,
                "ranking": ranking_report,
            }
        )
    return results


def _deterministic_candidate(
    repo_root: Path,
    commit: str,
    finding: NormalizedFinding,
    validator: ValidatorFn | None,
    finding_dir: Path,
) -> Candidate | None:
    bundle = generate_patches(repo_root, [finding])
    if not bundle.combined_diff:
        return None
    diff = bundle.combined_diff
    diff_path = finding_dir / "candidate_det.diff"
    diff_path.write_text(diff, encoding="utf-8")
    validation = _validate(validator, repo_root, commit, diff_path, finding_dir, "det")
    return Candidate(
        candidate_id="det-0",
        diff=diff,
        source="deterministic",
        diff_ok=True,
        validated=validation.ok,
        validation_status=validation.status,
    )


def _validate(
    validator: ValidatorFn | None,
    repo_root: Path,
    commit: str,
    diff_path: Path,
    finding_dir: Path,
    label: str,
) -> ValidationResult:
    if validator is None:
        return _run_validator_subprocess(repo_root, commit, diff_path, finding_dir, label)
    return validator(repo_root, commit, diff_path)


def _run_validator_subprocess(
    repo_root: Path,
    commit: str,
    diff_path: Path,
    finding_dir: Path,
    label: str,
) -> ValidationResult:
    cmd = [
        "python",
        "-m",
        "validator.runner",
        "--repo",
        str(repo_root),
        "--commit",
        commit,
        "--patch",
        str(diff_path),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    report_path = finding_dir / f"validation_{label}.json"
    if proc.stdout:
        report_path.write_text(proc.stdout, encoding="utf-8")
    ok = proc.returncode == 0 and '"validated"' in proc.stdout
    status = "validated" if ok else "rejected"
    return ValidationResult(ok=ok, status=status, report_path=str(report_path))


def _build_context(repo_root: Path, finding: NormalizedFinding) -> dict[str, Any]:
    path = repo_root / finding.filepath
    snippet = _extract_snippet(path, finding.start_line, finding.end_line, context=4)
    return {
        "finding": {
            "finding_id": finding.finding_id,
            "rule_id": finding.rule_id,
            "category": finding.category,
            "filepath": finding.filepath,
            "start_line": finding.start_line,
            "end_line": finding.end_line,
            "safe_fix": finding.extra.get("safe_fix") if finding.extra else None,
        },
        "snippet": snippet,
    }


def _extract_snippet(path: Path, start_line: int, end_line: int, context: int) -> str:
    if not path.exists():
        return ""
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    start = max(start_line - context, 1)
    end = min(end_line + context, len(lines))
    return "\n".join(lines[start - 1 : end])


def _retrieve_citations(retriever: RAGRetriever, finding: NormalizedFinding) -> list[str]:
    query = f"{finding.category} {finding.rule_id} {finding.filepath}"
    hits = retriever.retrieve(query, top_k=5)
    citations = []
    for idx, hit in enumerate(hits, start=1):
        citations.append(f"[CIT-{idx}] {hit.title} ({hit.source_path}) — {hit.snippet}")
    return citations


def _build_prompt_text(context: dict[str, Any], citations: list[str]) -> str:
    return (
        "Return ONLY a unified diff. No prose. No commands. Minimal localized edits.\n"
        f"Finding: {json.dumps(context.get('finding'))}\n"
        f"Snippet:\n{context.get('snippet')}\n"
        "Citations:\n" + "\n".join(citations)
    )


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _redact_context(context: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(context)
    if "snippet" in redacted:
        redacted["snippet"] = redact_text(str(redacted["snippet"]))
    return redacted


def _run_id(commit: str, findings: list[dict[str, Any]] | list[NormalizedFinding]) -> str:
    ids: list[str] = []
    for item in findings:
        if isinstance(item, NormalizedFinding):
            ids.append(item.finding_id)
        else:
            ids.append(str(item.get("finding_id") or ""))
    payload = commit + "|" + "|".join(sorted(ids))
    return sha1(payload.encode("utf-8")).hexdigest()[:12]
