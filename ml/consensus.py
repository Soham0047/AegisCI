"""
Scanner Consensus Module

Combines findings from multiple scanners to compute confidence scores
based on cross-scanner agreement. When multiple scanners flag the same
code location, confidence is boosted.

Scanner Sources:
1. Bandit - Python security analysis
2. Semgrep - Multi-language pattern matching
3. Secrets Scanner - Hardcoded credential detection
4. Pattern Scanner - Dangerous code patterns
5. Dependency Scanner - Known CVE detection
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class UnifiedFinding:
    """A security finding with consensus scoring from multiple scanners."""
    
    finding_id: str
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    category: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: str  # HIGH, MEDIUM, LOW
    
    # Scanner sources that flagged this
    scanner_sources: list[str] = field(default_factory=list)
    scanner_details: dict[str, dict[str, Any]] = field(default_factory=dict)
    
    # Consensus metrics
    consensus_score: float = 0.0  # 0.0 to 1.0
    scanner_count: int = 0
    
    # Original messages from each scanner
    messages: list[str] = field(default_factory=list)
    
    # Enhanced features for ML
    features: dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        self.scanner_count = len(self.scanner_sources)
        self._compute_consensus_score()
    
    def _compute_consensus_score(self) -> None:
        """Compute confidence based on scanner agreement."""
        # Base score from severity
        severity_weights = {
            "CRITICAL": 1.0,
            "HIGH": 0.8,
            "MEDIUM": 0.6,
            "LOW": 0.4,
            "INFO": 0.2,
        }
        base_score = severity_weights.get(self.severity.upper(), 0.5)
        
        # Confidence modifier
        confidence_weights = {
            "HIGH": 1.0,
            "MEDIUM": 0.75,
            "LOW": 0.5,
        }
        confidence_mod = confidence_weights.get(self.confidence.upper(), 0.5)
        
        # Scanner agreement boost (more scanners = higher confidence)
        # 1 scanner: 0.6, 2: 0.75, 3: 0.85, 4: 0.92, 5: 1.0
        agreement_boost = min(1.0, 0.5 + (self.scanner_count * 0.1))
        
        self.consensus_score = base_score * confidence_mod * agreement_boost
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "finding_id": self.finding_id,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "code_snippet": self.code_snippet,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "scanner_sources": self.scanner_sources,
            "scanner_details": self.scanner_details,
            "consensus_score": self.consensus_score,
            "scanner_count": self.scanner_count,
            "messages": self.messages,
            "features": self.features,
        }


def _generate_finding_id(file_path: str, line: int, category: str) -> str:
    """Generate a unique ID for a finding based on location."""
    content = f"{file_path}:{line}:{category}"
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def _normalize_severity(severity: str) -> str:
    """Normalize severity levels across scanners."""
    severity = str(severity).upper()
    mapping = {
        # Bandit
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        # Semgrep
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
        # Custom
        "CRITICAL": "CRITICAL",
        "UNDEFINED": "MEDIUM",
    }
    return mapping.get(severity, "MEDIUM")


def _normalize_confidence(confidence: str) -> str:
    """Normalize confidence levels across scanners."""
    confidence = str(confidence).upper()
    mapping = {
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "UNDEFINED": "MEDIUM",
    }
    return mapping.get(confidence, "MEDIUM")


def _normalize_category(category: str, scanner: str) -> str:
    """Normalize category names across scanners."""
    category = str(category).lower()
    
    # Map to unified categories
    if any(x in category for x in ["sql", "injection"]):
        return "sql.injection"
    if any(x in category for x in ["command", "exec", "os.", "subprocess"]):
        return "command.injection"
    if any(x in category for x in ["xss", "script", "html"]):
        return "xss"
    if any(x in category for x in ["secret", "password", "api_key", "token", "credential"]):
        return "hardcoded.secrets"
    if any(x in category for x in ["pickle", "deserial", "yaml", "marshal"]):
        return "deserialization"
    if any(x in category for x in ["crypto", "hash", "md5", "sha1", "random"]):
        return "crypto.weak"
    if any(x in category for x in ["path", "traversal", "file"]):
        return "path.traversal"
    if any(x in category for x in ["ssrf", "request"]):
        return "ssrf"
    if any(x in category for x in ["cve", "vuln", "dependency"]):
        return "dependency.vulnerability"
    
    return category


def _extract_location_key(finding: dict[str, Any], scanner: str) -> tuple[str, int, int]:
    """Extract file path and line range from a finding."""
    if scanner == "bandit":
        return (
            finding.get("filename", ""),
            finding.get("line_number", 0),
            finding.get("line_number", 0) + finding.get("line_range", [0])[-1] - 1 if finding.get("line_range") else finding.get("line_number", 0),
        )
    elif scanner == "semgrep":
        return (
            finding.get("path", ""),
            finding.get("start", {}).get("line", 0),
            finding.get("end", {}).get("line", 0),
        )
    elif scanner == "secrets":
        return (
            finding.get("file_path", finding.get("file", "")),
            finding.get("line_number", finding.get("line", 0)),
            finding.get("line_number", finding.get("line", 0)),
        )
    elif scanner == "patterns":
        return (
            finding.get("file_path", finding.get("file", "")),
            finding.get("line", finding.get("line_number", 0)),
            finding.get("line", finding.get("line_number", 0)),
        )
    elif scanner == "dependencies":
        # Dependencies don't have line numbers
        return (
            finding.get("file_path", finding.get("manifest", "")),
            0,
            0,
        )
    return ("", 0, 0)


def _extract_code_snippet(finding: dict[str, Any], scanner: str) -> str:
    """Extract code snippet from a finding."""
    if scanner == "bandit":
        return finding.get("code", "")
    elif scanner == "semgrep":
        return finding.get("extra", {}).get("lines", "")
    elif scanner in ("secrets", "patterns"):
        return finding.get("matched_text", finding.get("code", finding.get("snippet", "")))
    elif scanner == "dependencies":
        return f"{finding.get('package', '')}=={finding.get('version', '')}"
    return ""


def merge_scanner_results(
    bandit_findings: list[dict[str, Any]] | None = None,
    semgrep_findings: list[dict[str, Any]] | None = None,
    secrets_findings: list[dict[str, Any]] | None = None,
    pattern_findings: list[dict[str, Any]] | None = None,
    dependency_findings: list[dict[str, Any]] | None = None,
) -> list[UnifiedFinding]:
    """
    Merge findings from all scanners into unified findings with consensus scoring.
    
    Findings at the same location (file + line range) are merged, and scanner
    agreement boosts the confidence score.
    """
    # Index findings by location
    location_index: dict[tuple[str, int], list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    
    scanners = [
        ("bandit", bandit_findings or []),
        ("semgrep", semgrep_findings or []),
        ("secrets", secrets_findings or []),
        ("patterns", pattern_findings or []),
        ("dependencies", dependency_findings or []),
    ]
    
    for scanner_name, findings in scanners:
        for finding in findings:
            file_path, line_start, line_end = _extract_location_key(finding, scanner_name)
            if file_path:
                # Use file + line_start as the key (within 3 lines tolerance)
                key = (file_path, line_start // 3)  # Group nearby lines
                location_index[key].append((scanner_name, finding))
    
    # Merge findings at same location
    unified_findings: list[UnifiedFinding] = []
    
    for (file_path, _), scanner_findings in location_index.items():
        if not scanner_findings:
            continue
        
        # Collect all scanner sources and details
        scanner_sources = []
        scanner_details = {}
        messages = []
        categories = []
        severities = []
        confidences = []
        code_snippets = []
        line_starts = []
        line_ends = []
        
        for scanner_name, finding in scanner_findings:
            scanner_sources.append(scanner_name)
            scanner_details[scanner_name] = finding
            
            # Extract details based on scanner
            if scanner_name == "bandit":
                messages.append(finding.get("issue_text", ""))
                categories.append(finding.get("test_id", "") + ":" + finding.get("test_name", ""))
                severities.append(finding.get("issue_severity", "MEDIUM"))
                confidences.append(finding.get("issue_confidence", "MEDIUM"))
            elif scanner_name == "semgrep":
                messages.append(finding.get("extra", {}).get("message", ""))
                categories.append(finding.get("check_id", ""))
                severities.append(finding.get("extra", {}).get("severity", "WARNING"))
                confidences.append("HIGH")  # Semgrep rules are generally high confidence
            elif scanner_name == "secrets":
                messages.append(f"Potential {finding.get('pattern_name', 'secret')} detected")
                categories.append(finding.get("pattern_name", "secret"))
                severities.append(finding.get("severity", "HIGH"))
                confidences.append(finding.get("confidence", "HIGH"))
            elif scanner_name == "patterns":
                messages.append(finding.get("message", finding.get("description", "")))
                categories.append(finding.get("pattern_id", finding.get("rule_id", "")))
                severities.append(finding.get("severity", "MEDIUM"))
                confidences.append(finding.get("confidence", "MEDIUM"))
            elif scanner_name == "dependencies":
                messages.append(f"CVE: {finding.get('cve_id', 'Unknown')} - {finding.get('description', '')}")
                categories.append("dependency.vulnerability")
                severities.append(finding.get("severity", "HIGH"))
                confidences.append("HIGH")
            
            # Get location
            fp, ls, le = _extract_location_key(finding, scanner_name)
            if ls > 0:
                line_starts.append(ls)
            if le > 0:
                line_ends.append(le)
            
            code_snippets.append(_extract_code_snippet(finding, scanner_name))
        
        # Aggregate - use highest severity, most common category
        final_severity = max(severities, key=lambda s: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(_normalize_severity(s), 2))
        final_confidence = max(confidences, key=lambda c: {"HIGH": 2, "MEDIUM": 1, "LOW": 0}.get(_normalize_confidence(c), 1))
        final_category = _normalize_category(categories[0] if categories else "unknown", scanner_sources[0])
        
        final_line_start = min(line_starts) if line_starts else 0
        final_line_end = max(line_ends) if line_ends else final_line_start
        final_snippet = max(code_snippets, key=len) if code_snippets else ""
        
        # Generate ID
        finding_id = _generate_finding_id(file_path, final_line_start, final_category)
        
        # Compute enhanced features
        features = compute_enhanced_features(
            code_snippet=final_snippet,
            category=final_category,
            scanner_sources=scanner_sources,
            severity=final_severity,
        )
        
        unified = UnifiedFinding(
            finding_id=finding_id,
            file_path=file_path,
            line_start=final_line_start,
            line_end=final_line_end,
            code_snippet=final_snippet,
            category=final_category,
            severity=_normalize_severity(final_severity),
            confidence=_normalize_confidence(final_confidence),
            scanner_sources=scanner_sources,
            scanner_details=scanner_details,
            messages=messages,
            features=features,
        )
        unified_findings.append(unified)
    
    # Sort by consensus score (highest first)
    unified_findings.sort(key=lambda f: f.consensus_score, reverse=True)
    
    return unified_findings


def compute_enhanced_features(
    code_snippet: str,
    category: str,
    scanner_sources: list[str],
    severity: str,
) -> dict[str, Any]:
    """
    Compute enhanced features for ML training based on multi-scanner data.
    """
    features = {
        # Scanner agreement features
        "scanner_count": len(scanner_sources),
        "has_bandit": "bandit" in scanner_sources,
        "has_semgrep": "semgrep" in scanner_sources,
        "has_secrets_scanner": "secrets" in scanner_sources,
        "has_pattern_scanner": "patterns" in scanner_sources,
        "has_dependency_scanner": "dependencies" in scanner_sources,
        
        # Agreement ratio (normalized to 0-1)
        "scanner_agreement_ratio": len(scanner_sources) / 5.0,
        
        # Severity encoding
        "severity_score": {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.6, "LOW": 0.4, "INFO": 0.2}.get(severity.upper(), 0.5),
        
        # Category encoding
        "is_injection": "injection" in category.lower(),
        "is_secrets": "secret" in category.lower() or "credential" in category.lower(),
        "is_crypto": "crypto" in category.lower(),
        "is_xss": "xss" in category.lower(),
        "is_path_traversal": "path" in category.lower(),
        "is_deserialization": "deserial" in category.lower() or "pickle" in category.lower(),
        "is_dependency_vuln": "dependency" in category.lower() or "cve" in category.lower(),
        
        # Code features
        "code_length": len(code_snippet),
        "has_user_input": any(x in code_snippet.lower() for x in ["request", "input", "args", "params", "query"]),
        "has_dangerous_function": any(x in code_snippet.lower() for x in ["eval", "exec", "system", "popen", "shell"]),
        "has_sql_keyword": any(x in code_snippet.upper() for x in ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP"]),
        "has_file_operation": any(x in code_snippet.lower() for x in ["open(", "read(", "write(", "file"]),
    }
    
    return features


def get_consensus_label(unified_finding: UnifiedFinding) -> int:
    """
    Determine the label (1=TP, 0=FP) based on consensus heuristics.
    
    Higher consensus = more likely to be true positive.
    """
    # High confidence thresholds
    if unified_finding.scanner_count >= 3:
        return 1  # Multiple scanners agree = likely TP
    
    if unified_finding.severity == "CRITICAL":
        return 1  # Critical severity = likely TP
    
    if unified_finding.scanner_count >= 2 and unified_finding.confidence == "HIGH":
        return 1  # Two high-confidence scanners = likely TP
    
    # Use consensus score threshold
    if unified_finding.consensus_score >= 0.6:
        return 1
    
    # Lower confidence = needs manual review (but lean towards TP for training)
    if unified_finding.consensus_score >= 0.4:
        return 1  # Include as TP with moderate confidence
    
    return 0  # Likely false positive


def compute_statistics(findings: list[UnifiedFinding]) -> dict[str, Any]:
    """Compute statistics about the merged findings."""
    if not findings:
        return {"total": 0}
    
    stats = {
        "total": len(findings),
        "by_severity": {},
        "by_category": {},
        "by_scanner_count": {},
        "avg_consensus_score": sum(f.consensus_score for f in findings) / len(findings),
        "scanner_coverage": {
            "bandit": sum(1 for f in findings if "bandit" in f.scanner_sources),
            "semgrep": sum(1 for f in findings if "semgrep" in f.scanner_sources),
            "secrets": sum(1 for f in findings if "secrets" in f.scanner_sources),
            "patterns": sum(1 for f in findings if "patterns" in f.scanner_sources),
            "dependencies": sum(1 for f in findings if "dependencies" in f.scanner_sources),
        },
    }
    
    for finding in findings:
        # By severity
        sev = finding.severity
        stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1
        
        # By category
        cat = finding.category
        stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1
        
        # By scanner count
        count = str(finding.scanner_count)
        stats["by_scanner_count"][count] = stats["by_scanner_count"].get(count, 0) + 1
    
    return stats
