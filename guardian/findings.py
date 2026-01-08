from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
DEFAULT_CONFIDENCE = 0.5

_REDACT_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----"),
]


@dataclass
class RuleInfo:
    rule_id: str
    name: str
    category: str


@dataclass
class Location:
    filepath: str
    start_line: int
    end_line: int
    start_col: int | None = None
    end_col: int | None = None


@dataclass
class Evidence:
    excerpt: str
    excerpt_language: str
    highlight: dict[str, Any] | None = None


@dataclass
class MLWhy:
    model: str
    risk_score: float
    category_pred: str
    category_confidence: float
    calibrated: bool
    ood: dict[str, Any] | None = None


@dataclass
class WhyInfo:
    tool_message: str | None
    ml: MLWhy | None
    rationale: str


@dataclass
class UnifiedFinding:
    finding_id: str
    severity: str
    confidence: float
    source: str
    rule: RuleInfo
    location: Location
    evidence: Evidence
    why: WhyInfo
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    remediation: str | None = None
    raw: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if not self.tags:
            data.pop("tags", None)
        if not self.references:
            data.pop("references", None)
        if self.remediation is None:
            data.pop("remediation", None)
        if self.raw is None:
            data.pop("raw", None)
        return data


def normalize_severity(raw: str | None) -> str:
    if not raw:
        return "info"
    value = str(raw).strip().lower()
    mapping = {
        "critical": "critical",
        "high": "high",
        "error": "high",
        "medium": "medium",
        "warning": "medium",
        "low": "low",
        "info": "info",
    }
    return mapping.get(value, "info")


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(severity.lower(), 0)


def normalize_confidence(raw: Any) -> float:
    if raw is None:
        return DEFAULT_CONFIDENCE
    if isinstance(raw, (int, float)):
        return float(max(0.0, min(1.0, raw)))
    value = str(raw).strip().lower()
    mapping = {"high": 0.9, "medium": 0.6, "low": 0.3}
    return mapping.get(value, DEFAULT_CONFIDENCE)


def build_finding_id(
    filepath: str,
    start_line: int,
    end_line: int,
    rule_id: str,
    source_key: str,
    primary_signal: str,
) -> str:
    payload = f"{filepath}:{start_line}:{end_line}:{rule_id}:{source_key}:{primary_signal}"
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:12]


def redact_secrets(text: str) -> str:
    redacted = text
    for pattern in _REDACT_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)

    def _mask_long_token(match: re.Match[str]) -> str:
        token = match.group(0)
        if len(token) >= 32:
            return "[REDACTED]"
        return token

    redacted = re.sub(r"[A-Za-z0-9_\-/=+]{32,}", _mask_long_token, redacted)
    return redacted


def _normalize_path(path: str, repo_root: Path | None) -> str:
    if not path:
        return "unknown"
    p = Path(path)
    try:
        if repo_root is not None:
            return p.resolve().relative_to(repo_root.resolve()).as_posix()
    except Exception:
        pass
    return p.as_posix().lstrip("./")


def _language_for_path(path: str) -> str:
    suffix = Path(path).suffix.lower()
    if suffix == ".py":
        return "python"
    if suffix in {".ts", ".tsx"}:
        return "ts"
    if suffix in {".js", ".jsx"}:
        return "js"
    return "text"


def build_excerpt(
    filepath: str,
    start_line: int,
    end_line: int,
    repo_root: Path | None,
    file_cache: dict[str, list[str]] | None = None,
    context_lines: int = 2,
    max_lines: int = 12,
    max_chars: int = 1200,
) -> Evidence:
    if file_cache is None:
        file_cache = {}
    path_key = filepath
    if path_key not in file_cache:
        try:
            text = Path(repo_root or Path(".")).joinpath(filepath).read_text(encoding="utf-8")
            file_cache[path_key] = text.splitlines()
        except Exception:
            file_cache[path_key] = []

    lines = file_cache.get(path_key, [])
    if not lines:
        return Evidence(excerpt="", excerpt_language=_language_for_path(filepath), highlight=None)

    start = max(1, start_line)
    end = max(start, end_line)
    snippet_start = max(1, start - context_lines)
    snippet_end = min(len(lines), end + context_lines)
    snippet_lines = lines[snippet_start - 1 : snippet_end]

    if len(snippet_lines) > max_lines:
        center = start - snippet_start
        half = max_lines // 2
        window_start = max(0, center - half)
        window_end = min(len(snippet_lines), window_start + max_lines)
        snippet_lines = snippet_lines[window_start:window_end]
        snippet_start += window_start
        snippet_end = snippet_start + len(snippet_lines) - 1

    highlight_lines = list(range(start, min(end, snippet_end) + 1))
    rendered: list[str] = []
    for idx, line in enumerate(snippet_lines, start=snippet_start):
        prefix = ">> " if idx in highlight_lines else "   "
        rendered.append(f"{prefix}{line}")

    excerpt = "\n".join(rendered)
    excerpt = redact_secrets(excerpt)
    if len(excerpt) > max_chars:
        excerpt = excerpt[: max_chars - 15].rstrip() + "...(truncated)"

    highlight = {"highlight_lines": highlight_lines} if highlight_lines else None
    return Evidence(
        excerpt=excerpt,
        excerpt_language=_language_for_path(filepath),
        highlight=highlight,
    )


def normalize_bandit_finding(
    item: dict[str, Any],
    repo_root: Path | None = None,
    file_cache: dict[str, list[str]] | None = None,
    context_lines: int = 2,
    max_lines: int = 12,
    max_chars: int = 1200,
) -> UnifiedFinding:
    filepath = _normalize_path(item.get("filename") or "", repo_root)
    line = int(item.get("line_number") or 1)
    rule_id = str(item.get("test_id") or "B???")
    issue_name = str(item.get("issue_name") or rule_id)
    message = str(item.get("issue_text") or issue_name)
    severity = normalize_severity(item.get("issue_severity"))
    confidence = normalize_confidence(item.get("issue_confidence"))
    evidence = build_excerpt(
        filepath,
        line,
        line,
        repo_root,
        file_cache=file_cache,
        context_lines=context_lines,
        max_lines=max_lines,
        max_chars=max_chars,
    )
    rule = RuleInfo(rule_id=rule_id, name=issue_name, category=rule_id)
    ml_info = None
    rationale = f"Bandit reported {issue_name} at line {line}."
    finding_id = build_finding_id(filepath, line, line, rule_id, "bandit", message)
    return UnifiedFinding(
        finding_id=finding_id,
        severity=severity,
        confidence=confidence,
        source="bandit",
        rule=rule,
        location=Location(filepath=filepath, start_line=line, end_line=line),
        evidence=evidence,
        why=WhyInfo(tool_message=message, ml=ml_info, rationale=rationale),
        raw=item,
    )


def normalize_semgrep_finding(
    item: dict[str, Any],
    repo_root: Path | None = None,
    file_cache: dict[str, list[str]] | None = None,
    context_lines: int = 2,
    max_lines: int = 12,
    max_chars: int = 1200,
) -> UnifiedFinding:
    filepath = _normalize_path(item.get("path") or "", repo_root)
    start = int((item.get("start") or {}).get("line") or 1)
    end = int((item.get("end") or {}).get("line") or start)
    extra = item.get("extra") or {}
    rule_id = str(item.get("check_id") or "semgrep")
    name = str(extra.get("message") or rule_id)
    severity = normalize_severity(extra.get("severity"))
    confidence = normalize_confidence(extra.get("confidence"))
    evidence = build_excerpt(
        filepath,
        start,
        end,
        repo_root,
        file_cache=file_cache,
        context_lines=context_lines,
        max_lines=max_lines,
        max_chars=max_chars,
    )
    rule = RuleInfo(rule_id=rule_id, name=name, category=str(rule_id))
    message = str(extra.get("message") or rule_id)
    rationale = f"Semgrep matched {rule_id} at line {start}."
    finding_id = build_finding_id(filepath, start, end, rule_id, "semgrep", message)
    return UnifiedFinding(
        finding_id=finding_id,
        severity=severity,
        confidence=confidence,
        source="semgrep",
        rule=rule,
        location=Location(filepath=filepath, start_line=start, end_line=end),
        evidence=evidence,
        why=WhyInfo(tool_message=message, ml=None, rationale=rationale),
        raw=item,
    )


def normalize_ml_finding(
    item: dict[str, Any],
    repo_root: Path | None = None,
    file_cache: dict[str, list[str]] | None = None,
    model_name: str | None = None,
    context_lines: int = 2,
    max_lines: int = 12,
    max_chars: int = 1200,
) -> UnifiedFinding | None:
    filepath = (
        item.get("filepath")
        or item.get("file")
        or item.get("path")
        or (item.get("location") or {}).get("filepath")
    )
    span = item.get("function_span") or item.get("span") or item.get("location") or {}
    start = span.get("start_line") or span.get("line") or item.get("line")
    end = span.get("end_line") or start
    if not filepath or not start:
        return None

    filepath_norm = _normalize_path(str(filepath), repo_root)
    start_line = int(start)
    end_line = int(end or start_line)

    risk_score = float(item.get("risk_score") or 0.0)
    top_categories = item.get("top_categories") or []
    category = "unknown"
    category_conf = 0.0
    if top_categories:
        top = top_categories[0]
        category = str(top.get("category") or "unknown")
        category_conf = float(top.get("confidence") or 0.0)

    severity = normalize_severity(
        "critical"
        if risk_score >= 0.9
        else "high"
        if risk_score >= 0.75
        else "medium"
        if risk_score >= 0.5
        else "low"
        if risk_score >= 0.25
        else "info"
    )
    confidence = max(0.0, min(1.0, risk_score))
    evidence = build_excerpt(
        filepath_norm,
        start_line,
        end_line,
        repo_root,
        file_cache=file_cache,
        context_lines=context_lines,
        max_lines=max_lines,
        max_chars=max_chars,
    )
    rule = RuleInfo(rule_id=category, name=category, category=category)
    ml_info = MLWhy(
        model=model_name or str(item.get("model") or "ml_ensemble"),
        risk_score=risk_score,
        category_pred=category,
        category_confidence=category_conf,
        calibrated=bool(item.get("calibrated", True)),
        ood=item.get("ood") if isinstance(item.get("ood"), dict) else None,
    )
    rationale = f"Model flagged {category} with risk score {risk_score:.2f}."
    finding_id = build_finding_id(
        filepath_norm, start_line, end_line, category, "ml", f"{risk_score:.3f}"
    )
    return UnifiedFinding(
        finding_id=finding_id,
        severity=severity,
        confidence=confidence,
        source=str(item.get("source") or "ml_ensemble"),
        rule=rule,
        location=Location(filepath=filepath_norm, start_line=start_line, end_line=end_line),
        evidence=evidence,
        why=WhyInfo(tool_message=None, ml=ml_info, rationale=rationale),
        raw=item,
    )


def merge_findings(
    tool_findings: list[UnifiedFinding],
    ml_findings: list[UnifiedFinding],
) -> list[UnifiedFinding]:
    dedup: dict[tuple[str, str, str, int, int], UnifiedFinding] = {}
    for finding in tool_findings:
        key = (
            finding.source,
            finding.rule.rule_id,
            finding.location.filepath,
            finding.location.start_line,
            finding.location.end_line,
        )
        dedup[key] = finding

    merged = list(dedup.values())

    for ml in ml_findings:
        candidate = _find_merge_candidate(merged, ml)
        if candidate:
            merged.remove(candidate)
            merged.append(_build_hybrid(candidate, ml))
        else:
            merged.append(ml)

    merged.sort(
        key=lambda f: (
            f.location.filepath,
            -severity_rank(f.severity),
            f.location.start_line,
            f.rule.rule_id,
        )
    )
    return merged


def _find_merge_candidate(
    findings: list[UnifiedFinding],
    ml: UnifiedFinding,
) -> UnifiedFinding | None:
    matches: list[UnifiedFinding] = []
    for finding in findings:
        if finding.source not in {"bandit", "semgrep"}:
            continue
        if finding.location.filepath != ml.location.filepath:
            continue
        if _spans_overlap(finding.location, ml.location):
            matches.append(finding)
    if not matches:
        return None
    matches.sort(
        key=lambda f: (
            f.location.end_line - f.location.start_line,
            f.location.start_line,
            f.rule.rule_id,
        )
    )
    return matches[0]


def _spans_overlap(a: Location, b: Location) -> bool:
    return not (a.end_line < b.start_line or b.end_line < a.start_line)


def _build_hybrid(tool: UnifiedFinding, ml: UnifiedFinding) -> UnifiedFinding:
    confidence = max(tool.confidence, ml.confidence)
    rationale = f"{tool.why.rationale} ML corroboration: {ml.why.rationale}"
    hybrid = UnifiedFinding(
        finding_id=build_finding_id(
            tool.location.filepath,
            tool.location.start_line,
            tool.location.end_line,
            tool.rule.rule_id,
            "hybrid",
            tool.why.tool_message or tool.rule.rule_id,
        ),
        severity=tool.severity,
        confidence=confidence,
        source="hybrid",
        rule=tool.rule,
        location=tool.location,
        evidence=tool.evidence,
        why=WhyInfo(tool_message=tool.why.tool_message, ml=ml.why.ml, rationale=rationale),
        tags=tool.tags,
        references=tool.references,
        remediation=tool.remediation,
        raw={"tool": tool.raw, "ml": ml.raw},
    )
    return hybrid
