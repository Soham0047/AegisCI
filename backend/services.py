import json
from typing import Any, Dict, List


def flatten_findings(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize Bandit + Semgrep into a single JSON structure for UI."""
    out: Dict[str, Any] = {"bandit": [], "semgrep": []}

    bandit = (raw.get("bandit") or {})
    for r in (bandit.get("results") or []):
        out["bandit"].append(
            {
                "test_id": r.get("test_id"),
                "severity": r.get("issue_severity"),
                "confidence": r.get("issue_confidence"),
                "filename": r.get("filename"),
                "line": r.get("line_number"),
                "message": r.get("issue_text"),
            }
        )

    semgrep = (raw.get("semgrep") or {})
    for r in (semgrep.get("results") or []):
        out["semgrep"].append(
            {
                "check_id": r.get("check_id"),
                "severity": (r.get("extra") or {}).get("severity"),
                "path": r.get("path"),
                "line": (r.get("start") or {}).get("line"),
                "message": (r.get("extra") or {}).get("message"),
            }
        )

    return out
