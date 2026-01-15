from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha1
from pathlib import Path
from typing import Any

from patcher import generate_patches
from patcher.diff import make_unified_diff, normalize_unified_diff
from patcher.llm_client import generate_patch, redact_text
from patcher.policy import decision_to_json, evaluate_llm_diff
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
                normalized = normalize_unified_diff(result.diff)
                rebased = _rebuild_diff_with_context(repo_root, normalized)
                diff_path.write_text(rebased, encoding="utf-8")
                policy = evaluate_llm_diff(rebased, finding, repo_root)
                _write_json(finding_dir / f"policy_{idx}.json", decision_to_json(policy))
                if not policy.allowed:
                    candidates_list.append(
                        Candidate(
                            candidate_id=f"llm-{idx}",
                            diff=rebased,
                            source="llm",
                            diff_ok=False,
                            validated=False,
                            validation_status=f"policy: {policy.reason}",
                            metadata={"policy": decision_to_json(policy)},
                        )
                    )
                    continue
                validation = _validate(
                    validator, repo_root, commit, diff_path, finding_dir, str(idx)
                )
                candidates_list.append(
                    Candidate(
                        candidate_id=f"llm-{idx}",
                        diff=rebased,
                        source="llm",
                        diff_ok=True,
                        validated=validation.ok,
                        validation_status=validation.status,
                        metadata={"validation_report": validation.report_path},
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
                        metadata={},
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
        metadata={"validation_report": validation.report_path},
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
    tool_root = Path(__file__).resolve().parents[1]
    dockerfile = tool_root / "docker" / "validator.Dockerfile"
    cmd = [
        sys.executable,
        "-m",
        "validator.runner",
        "--repo",
        str(repo_root),
        "--commit",
        commit,
        "--patch",
        str(diff_path),
    ]
    if dockerfile.exists():
        cmd.extend(["--dockerfile", str(dockerfile)])
    if os.getenv("VALIDATOR_ALLOW_NETWORK", "").lower() in {"1", "true", "yes"}:
        cmd.append("--allow-network")
    lint_mode = os.getenv("VALIDATOR_LINT_MODE")
    if lint_mode in {"strict", "changed", "off"}:
        cmd.extend(["--lint-mode", lint_mode])
    test_mode = os.getenv("VALIDATOR_TEST_MODE")
    if test_mode in {"strict", "off"}:
        cmd.extend(["--test-mode", test_mode])
    if os.getenv("VALIDATOR_BASELINE", "").lower() in {"1", "true", "yes"}:
        cmd.append("--baseline")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    report_path = finding_dir / f"validation_{label}.json"
    (finding_dir / f"validation_{label}.out").write_text(proc.stdout or "", encoding="utf-8")
    (finding_dir / f"validation_{label}.err").write_text(proc.stderr or "", encoding="utf-8")

    report = None
    if proc.stdout:
        try:
            report = json.loads(proc.stdout)
        except Exception:
            report = None
    if report is None and proc.stderr:
        try:
            report = json.loads(proc.stderr)
        except Exception:
            report = None

    if report is None:
        report = {
            "status": "rejected" if proc.returncode != 0 else "unknown",
            "reason": proc.stderr.strip() or proc.stdout.strip() or "unknown validator output",
        }

    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    ok = report.get("status") == "validated"
    status = "validated" if ok else "rejected"
    return ValidationResult(ok=ok, status=status, report_path=str(report_path))


def _rebuild_diff_with_context(repo_root: Path, diff_text: str) -> str:
    if not diff_text.strip():
        return diff_text
    if shutil.which("patch") is None:
        return diff_text
    path = _extract_single_path(diff_text)
    if path is None:
        return diff_text
    source_path = repo_root / path
    if not source_path.exists():
        return diff_text
    old_text = source_path.read_text(encoding="utf-8")
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_root = Path(temp_dir)
        temp_path = temp_root / path
        temp_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path.write_text(old_text, encoding="utf-8")
        proc = subprocess.run(
            ["patch", "-p1", "--fuzz=0", "--quiet"],
            input=diff_text,
            text=True,
            capture_output=True,
            cwd=temp_root,
        )
        if proc.returncode != 0:
            return diff_text
        new_text = temp_path.read_text(encoding="utf-8")
    if new_text == old_text:
        return diff_text
    return make_unified_diff(path, old_text, new_text)


def _extract_single_path(diff_text: str) -> str | None:
    paths: list[str] = []
    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            parts = line.split()
            if len(parts) >= 4:
                path = parts[3]
                if path.startswith("b/"):
                    path = path[2:]
                paths.append(path)
        elif line.startswith("+++ "):
            path = line[4:].strip()
            if path.startswith("b/"):
                path = path[2:]
            if path and path != "/dev/null":
                paths.append(path)
    unique = []
    for path in paths:
        if path not in unique:
            unique.append(path)
    if len(unique) == 1:
        return unique[0]
    return None


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
    """Retrieve relevant security knowledge for a finding."""
    citations: list[str] = []

    # 1. Try to get fix patterns first (most actionable)
    language = _detect_language(finding.filepath)
    fix_hits = retriever.retrieve_fix_pattern(
        category=finding.category or finding.rule_id,
        language=language,
        top_k=2,
    )
    for idx, hit in enumerate(fix_hits, start=1):
        citations.append(f"[FIX-{idx}] {hit.title} — {hit.snippet}")

    # 2. Get rule-specific documentation
    if finding.rule_id:
        rule_hits = retriever.retrieve_by_rule(finding.rule_id, top_k=2)
        for idx, hit in enumerate(rule_hits, start=1):
            # Avoid duplicates
            if not any(hit.chunk_id in c for c in citations):
                citations.append(f"[RULE-{idx}] {hit.title} — {hit.snippet}")

    # 3. General context query as fallback
    if len(citations) < 3:
        query = f"{finding.category} {finding.rule_id} {language} security fix"
        general_hits = retriever.retrieve(query, top_k=3)
        for idx, hit in enumerate(general_hits, start=1):
            if len(citations) >= 5:
                break
            # Avoid duplicates
            if not any(hit.chunk_id in c for c in citations):
                citations.append(f"[CIT-{idx}] {hit.title} ({hit.source_path}) — {hit.snippet}")

    return citations[:5]  # Limit to 5 citations


def _detect_language(filepath: str) -> str:
    """Detect programming language from file path."""
    ext_map = {
        ".py": "Python",
        ".js": "JavaScript",
        ".ts": "TypeScript",
        ".jsx": "JavaScript",
        ".tsx": "TypeScript",
        ".java": "Java",
        ".go": "Go",
        ".rb": "Ruby",
        ".php": "PHP",
        ".cs": "C#",
        ".cpp": "C++",
        ".c": "C",
        ".rs": "Rust",
    }
    from pathlib import Path as P

    suffix = P(filepath).suffix.lower()
    return ext_map.get(suffix, "unknown")


def _build_prompt_text(context: dict[str, Any], citations: list[str]) -> str:
    """Build the prompt for patch generation with rich context."""
    finding = context.get("finding", {})
    snippet = context.get("snippet", "")

    # Build structured prompt
    prompt_parts = [
        "You are a security expert. Generate a minimal, targeted fix for this vulnerability.",
        "",
        "## Vulnerability Details",
        f"- Rule: {finding.get('rule_id', 'unknown')}",
        f"- Category: {finding.get('category', 'unknown')}",
        f"- File: {finding.get('filepath', 'unknown')}",
        f"- Line: {finding.get('start_line', '?')}-{finding.get('end_line', '?')}",
        f"- Message: {finding.get('message', '')}",
        "",
        "## Vulnerable Code",
        "```",
        snippet,
        "```",
        "",
        "## Security Knowledge Base",
    ]

    if citations:
        for citation in citations:
            prompt_parts.append(f"- {citation}")
    else:
        prompt_parts.append("- No specific guidance available")

    prompt_parts.extend(
        [
            "",
            "## Instructions",
            "1. Return ONLY a unified diff (no prose, no commands)",
            "2. Make minimal, localized changes",
            "3. Preserve existing functionality",
            "4. Follow the fix patterns from the knowledge base",
            "5. Add any necessary imports",
            "",
            "## Output Format",
            "```diff",
            "--- a/path/to/file",
            "+++ b/path/to/file",
            "@@ ... @@",
            " context line",
            "-removed line",
            "+added line",
            "```",
        ]
    )

    return "\n".join(prompt_parts)


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
