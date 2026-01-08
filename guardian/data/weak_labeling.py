from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Any

from guardian.data.mapping import build_span_index, match_by_enclosing_span, match_nearest_span

LOGGER = logging.getLogger(__name__)
VERSION_RE = re.compile(r"(\d+\.\d+\.\d+)")


def _normalize_path(path: str, repo_root: Path) -> str:
    if not path:
        return ""
    path_obj = Path(path)
    candidates = [path_obj]
    if not path_obj.is_absolute():
        try:
            candidates.append(path_obj.resolve())
        except OSError:
            pass
    for candidate in candidates:
        try:
            rel = candidate.relative_to(repo_root)
            return rel.as_posix()
        except ValueError:
            continue
    parts = path_obj.parts
    if repo_root.name in parts:
        idx = parts.index(repo_root.name)
        rel_parts = parts[idx + 1 :]
        if rel_parts:
            return Path(*rel_parts).as_posix()
    return path_obj.as_posix()


def _parse_version(output: str) -> str:
    match = VERSION_RE.search(output)
    return match.group(1) if match else "unknown"


def _run_command(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=False, capture_output=True, text=True)


def get_tool_version(tool: str) -> str:
    try:
        result = _run_command([tool, "--version"])
    except FileNotFoundError:
        return "unknown"
    return _parse_version(result.stdout + "\n" + result.stderr)


def run_bandit(files: list[Path], args: list[str]) -> dict[str, Any]:
    if not files:
        return {"results": [], "errors": []}
    cmd = ["bandit", *args, *[str(f) for f in files]]
    try:
        result = _run_command(cmd)
    except FileNotFoundError:
        return {"results": [], "errors": ["bandit not installed"]}
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"results": [], "errors": [result.stderr.strip() or "bandit failed"]}


def run_semgrep(files: list[Path], args: list[str], config: str) -> dict[str, Any]:
    if not files:
        return {"results": [], "errors": []}
    cmd = ["semgrep", "--config", config, *args, *[str(f) for f in files]]
    try:
        result = _run_command(cmd)
    except FileNotFoundError:
        return {"results": [], "errors": ["semgrep not installed"]}
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"results": [], "errors": [result.stderr.strip() or "semgrep failed"]}


def parse_bandit_results(bandit_json: dict[str, Any], repo_root: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for result in bandit_json.get("results", []) or []:
        findings.append(
            {
                "source": "bandit",
                "rule_id": result.get("test_id") or "unknown",
                "severity": result.get("issue_severity") or "UNKNOWN",
                "confidence": result.get("issue_confidence"),
                "message": result.get("issue_text") or result.get("issue_name") or "",
                "line": result.get("line_number"),
                "filepath": _normalize_path(result.get("filename") or "", repo_root),
                "extra": {
                    "test_name": result.get("test_name"),
                    "issue_name": result.get("issue_name"),
                },
            }
        )
    return findings


def parse_semgrep_results(semgrep_json: dict[str, Any], repo_root: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for result in semgrep_json.get("results", []) or []:
        extra = result.get("extra") or {}
        findings.append(
            {
                "source": "semgrep",
                "rule_id": result.get("check_id") or "unknown",
                "severity": extra.get("severity") or "INFO",
                "confidence": None,
                "message": extra.get("message") or result.get("check_id") or "",
                "line": (result.get("start") or {}).get("line"),
                "filepath": _normalize_path(result.get("path") or "", repo_root),
                "extra": {
                    "metadata": extra.get("metadata")
                    if isinstance(extra.get("metadata"), dict)
                    else {},
                },
            }
        )
    return findings


def write_tool_outputs_for_repo(
    repo_root: Path,
    out_dir: Path,
    bandit_args: list[str],
    semgrep_args: list[str],
    semgrep_config: str,
    max_files: int | None,
    reuse: bool,
) -> dict[str, Any]:
    repo_name = repo_root.name
    repo_out = out_dir / repo_name
    repo_out.mkdir(parents=True, exist_ok=True)

    bandit_path = repo_out / "bandit.json"
    semgrep_path = repo_out / "semgrep.json"
    meta_path = repo_out / "meta.json"

    bandit_version = get_tool_version("bandit")
    semgrep_version = get_tool_version("semgrep")

    if reuse and bandit_path.exists() and semgrep_path.exists() and meta_path.exists():
        return json.loads(meta_path.read_text(encoding="utf-8"))

    py_files = _iter_files(repo_root, {".py"}, max_files)
    ts_files = _iter_files(repo_root, {".ts", ".tsx", ".js", ".jsx"}, max_files)

    bandit_json = run_bandit(py_files, bandit_args)
    semgrep_json = run_semgrep(ts_files, semgrep_args, semgrep_config)

    bandit_path.write_text(json.dumps(bandit_json, indent=2), encoding="utf-8")
    semgrep_path.write_text(json.dumps(semgrep_json, indent=2), encoding="utf-8")

    meta = {
        "repo": f"local/{repo_name}",
        "bandit": {"version": bandit_version, "args": bandit_args},
        "semgrep": {"version": semgrep_version, "args": semgrep_args, "config": semgrep_config},
    }
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def _iter_files(repo_root: Path, extensions: set[str], max_files: int | None) -> list[Path]:
    files: list[Path] = []
    for root, dirs, filenames in os.walk(repo_root):
        dirs[:] = [
            d
            for d in dirs
            if not d.startswith(".")
            and d not in {"node_modules", "dist", "build", ".git", "venv", "site-packages"}
        ]
        for filename in filenames:
            path = Path(root) / filename
            if path.suffix in extensions:
                files.append(path)
                if max_files and len(files) >= max_files:
                    return files
    return files


def map_findings_to_samples(
    samples: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    repo_id: str,
    max_distance: int = 3,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, int]]:
    index = build_span_index(samples)
    mapped: dict[str, list[dict[str, Any]]] = {}
    total = 0
    matched = 0

    for finding in findings:
        total += 1
        filepath = finding.get("filepath") or ""
        line = finding.get("line")
        if not filepath or not isinstance(line, int):
            continue
        sample_id = match_by_enclosing_span(index, repo_id, filepath, line)
        if not sample_id:
            sample_id = match_nearest_span(
                index, repo_id, filepath, line, max_distance=max_distance
            )
        if not sample_id:
            continue
        matched += 1
        label = {
            "source": finding.get("source") or "unknown",
            "rule_id": finding.get("rule_id") or "unknown",
            "severity": finding.get("severity") or "UNKNOWN",
            "confidence": finding.get("confidence"),
            "message": finding.get("message") or "",
            "line": line,
            "extra": finding.get("extra") or {},
        }
        mapped.setdefault(sample_id, []).append(label)

    return mapped, {"total": total, "mapped": matched}


def load_tool_outputs(
    repo_root: Path, tool_dir: Path
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    repo_name = repo_root.name
    repo_out = tool_dir / repo_name
    bandit_path = repo_out / "bandit.json"
    semgrep_path = repo_out / "semgrep.json"
    meta_path = repo_out / "meta.json"

    findings: list[dict[str, Any]] = []
    if bandit_path.exists():
        findings.extend(
            parse_bandit_results(json.loads(bandit_path.read_text(encoding="utf-8")), repo_root)
        )
    if semgrep_path.exists():
        findings.extend(
            parse_semgrep_results(json.loads(semgrep_path.read_text(encoding="utf-8")), repo_root)
        )

    tool_versions: dict[str, Any] = {}
    if meta_path.exists():
        tool_versions = json.loads(meta_path.read_text(encoding="utf-8"))
    return findings, tool_versions
