from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _normalize_path(path: str) -> str:
    return Path(path).as_posix().lstrip("./")


def _normalize_label(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "source": raw.get("source") or "unknown",
        "rule_id": raw.get("rule_id") or "unknown",
        "severity": raw.get("severity") or "UNKNOWN",
        "confidence": raw.get("confidence"),
        "message": raw.get("message") or "",
        "line": raw.get("line"),
        "filepath": _normalize_path(
            raw.get("filepath") or raw.get("file") or raw.get("path") or ""
        ),
        "extra": raw.get("extra") or {},
        "repo": raw.get("repo"),
    }


def _labels_from_report(report: dict[str, Any]) -> list[dict[str, Any]]:
    labels: list[dict[str, Any]] = []
    bandit_results = (report.get("bandit") or {}).get("results") or []
    for result in bandit_results:
        labels.append(
            {
                "source": "bandit",
                "rule_id": result.get("test_id") or "unknown",
                "severity": result.get("issue_severity") or "UNKNOWN",
                "confidence": result.get("issue_confidence"),
                "message": result.get("issue_text") or result.get("issue_name") or "",
                "line": result.get("line_number"),
                "filepath": result.get("filename") or "",
                "extra": {},
            }
        )

    semgrep_results = (report.get("semgrep") or {}).get("results") or []
    for result in semgrep_results:
        extra = result.get("extra") or {}
        labels.append(
            {
                "source": "semgrep",
                "rule_id": result.get("check_id") or "unknown",
                "severity": extra.get("severity") or "INFO",
                "confidence": extra.get("confidence"),
                "message": extra.get("message") or result.get("check_id") or "",
                "line": (result.get("start") or {}).get("line"),
                "filepath": result.get("path") or "",
                "extra": {},
            }
        )
    return labels


def load_labels(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not path:
        return [], {}
    content = path.read_text(encoding="utf-8")
    tool_versions: dict[str, Any] = {}
    raw_labels: list[dict[str, Any]] = []

    if path.suffix == ".jsonl":
        for line in content.splitlines():
            if not line.strip():
                continue
            raw_labels.append(json.loads(line))
    else:
        data = json.loads(content)
        if isinstance(data, dict):
            if "tool_versions" in data and isinstance(data["tool_versions"], dict):
                tool_versions = data["tool_versions"]
            if "findings" in data and isinstance(data["findings"], list):
                raw_labels = data["findings"]
            elif "bandit" in data or "semgrep" in data:
                raw_labels = _labels_from_report(data)
            elif "items" in data and isinstance(data["items"], list):
                raw_labels = data["items"]
            else:
                raw_labels = []
        elif isinstance(data, list):
            raw_labels = data

    normalized = [_normalize_label(label) for label in raw_labels]
    return normalized, tool_versions


def build_label_index(
    labels: list[dict[str, Any]],
) -> dict[tuple[str | None, str], list[dict[str, Any]]]:
    index: dict[tuple[str | None, str], list[dict[str, Any]]] = {}
    for label in labels:
        filepath = _normalize_path(label.get("filepath") or "")
        repo = label.get("repo")
        key = (repo, filepath)
        index.setdefault(key, []).append(label)
    return index


def attach_weak_labels(
    samples: list[dict[str, Any]],
    label_index: dict[tuple[str | None, str], list[dict[str, Any]]],
    repo_id: str,
) -> None:
    for sample in samples:
        filepath = _normalize_path(sample.get("filepath") or "")
        span = sample.get("function_span") or {}
        start = span.get("start_line")
        end = span.get("end_line")
        if not start or not end:
            continue

        candidates = label_index.get((repo_id, filepath), []) + label_index.get(
            (None, filepath), []
        )
        matched: list[dict[str, Any]] = []
        for label in candidates:
            line = label.get("line")
            if line is None:
                continue
            if start <= line <= end:
                matched.append(
                    {
                        "source": label.get("source") or "unknown",
                        "rule_id": label.get("rule_id") or "unknown",
                        "severity": label.get("severity") or "UNKNOWN",
                        "confidence": label.get("confidence"),
                        "message": label.get("message") or "",
                        "line": line,
                        "extra": label.get("extra") or {},
                    }
                )
        sample["weak_labels"] = matched
