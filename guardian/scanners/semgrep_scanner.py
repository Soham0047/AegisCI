"""
Enhanced Semgrep Scanner with comprehensive security rulesets.

Runs multiple Semgrep configurations for maximum vulnerability detection:
- p/security-audit: Comprehensive security audit rules
- p/owasp-top-ten: OWASP Top 10 vulnerabilities
- p/secrets: Hardcoded secrets detection
- p/python: Python-specific security issues
- p/javascript: JavaScript/TypeScript security issues
- p/nodejs: Node.js specific vulnerabilities
- p/react: React security issues
- p/typescript: TypeScript-specific issues
- p/sql-injection: SQL injection detection
- p/xss: Cross-site scripting detection
- p/command-injection: Command injection detection
"""

import json
import subprocess
from typing import Any


# Comprehensive Semgrep rulesets for different vulnerability categories
SEMGREP_RULESETS = {
    # Core security rulesets
    "security-audit": "p/security-audit",
    "owasp": "p/owasp-top-ten",
    "secrets": "p/secrets",
    
    # Language-specific rulesets
    "python": "p/python",
    "javascript": "p/javascript",
    "typescript": "p/typescript",
    "nodejs": "p/nodejs",
    "react": "p/react",
    
    # Vulnerability-specific rulesets
    "sql-injection": "p/sql-injection",
    "xss": "p/xss",
    "command-injection": "p/command-injection",
    
    # Framework-specific
    "django": "p/django",
    "flask": "p/flask",
    "express": "p/express",
    "nextjs": "p/nextjs",
    
    # Default CI ruleset
    "ci": "p/ci",
}

# Default rulesets to run for comprehensive scanning
DEFAULT_RULESETS = [
    "p/security-audit",
    "p/owasp-top-ten", 
    "p/secrets",
]

# Language-specific ruleset mapping
LANGUAGE_RULESETS = {
    ".py": ["p/python", "p/django", "p/flask"],
    ".js": ["p/javascript", "p/nodejs", "p/express", "p/react"],
    ".ts": ["p/typescript", "p/nodejs", "p/express", "p/react"],
    ".tsx": ["p/typescript", "p/react", "p/nextjs"],
    ".jsx": ["p/javascript", "p/react"],
}


def run_semgrep(
    files: list[str],
    config: str | list[str] = "p/ci",
    timeout: int = 300,
    max_target_bytes: int = 1_000_000,
    include_experimental: bool = False,
    autofix: bool = False,
) -> dict[str, Any]:
    """
    Run Semgrep on provided files with comprehensive security rules.
    
    Args:
        files: List of files to scan
        config: Semgrep config (single or multiple rulesets)
        timeout: Timeout in seconds for entire scan
        max_target_bytes: Max file size to scan
        include_experimental: Include experimental rules
        autofix: Include autofix suggestions
    
    Returns:
        JSON-like dict with results and errors
    """
    if not files:
        return {"results": [], "errors": [], "paths": {"scanned": []}}

    # Build command with configs
    cmd = [
        "semgrep",
        "--json",
        "--timeout", str(timeout),
        "--max-target-bytes", str(max_target_bytes),
        "--no-git-ignore",  # Scan all files, not just tracked
        "--metrics", "off",  # Don't send metrics
    ]
    
    # Add configs
    if isinstance(config, str):
        configs = [config]
    else:
        configs = config
    
    for cfg in configs:
        cmd.extend(["--config", cfg])
    
    # Add experimental flag
    if include_experimental:
        cmd.append("--include-experimental")
    
    # Add autofix flag
    if autofix:
        cmd.append("--autofix")
        cmd.append("--dryrun")  # Don't actually modify files
    
    # Add files
    cmd.extend(files)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 30,  # Extra buffer for startup
        )
        
        # Semgrep may exit non-zero on findings
        output = result.stdout or result.stderr
        try:
            data = json.loads(output)
            data["scanner"] = "semgrep"
            data["version"] = _get_semgrep_version()
            data["configs_used"] = configs
            return data
        except json.JSONDecodeError:
            return {
                "results": [],
                "errors": [f"Failed to parse semgrep output: {output[:500]}"],
                "paths": {"scanned": files},
            }
            
    except FileNotFoundError:
        return {
            "results": [],
            "errors": ["semgrep not installed - run: pip install semgrep"],
            "paths": {"scanned": []},
        }
    except subprocess.TimeoutExpired:
        return {
            "results": [],
            "errors": [f"semgrep timed out after {timeout}s"],
            "paths": {"scanned": files},
        }
    except Exception as e:
        return {
            "results": [],
            "errors": [f"semgrep failed: {e}"],
            "paths": {"scanned": []},
        }


def run_semgrep_comprehensive(files: list[str]) -> dict[str, Any]:
    """
    Run Semgrep with comprehensive security rulesets.
    
    Automatically selects appropriate rulesets based on file extensions.
    """
    if not files:
        return {"results": [], "errors": [], "paths": {"scanned": []}}
    
    # Determine which rulesets to use based on file types
    rulesets = set(DEFAULT_RULESETS)
    
    for file in files:
        for ext, ext_rulesets in LANGUAGE_RULESETS.items():
            if file.endswith(ext):
                rulesets.update(ext_rulesets)
    
    return run_semgrep(files, config=list(rulesets))


def run_semgrep_secrets(files: list[str]) -> dict[str, Any]:
    """Run Semgrep specifically for secrets detection."""
    return run_semgrep(files, config="p/secrets")


def run_semgrep_owasp(files: list[str]) -> dict[str, Any]:
    """Run Semgrep with OWASP Top 10 rules."""
    return run_semgrep(files, config="p/owasp-top-ten")


def _get_semgrep_version() -> str:
    """Get installed Semgrep version."""
    try:
        result = subprocess.run(
            ["semgrep", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() if result.returncode == 0 else "unknown"
    except Exception:
        return "unknown"


# Semgrep rule categories for reporting
SEMGREP_CATEGORIES = {
    "injection": [
        "sql-injection", "command-injection", "code-injection",
        "ldap-injection", "xpath-injection", "nosql-injection"
    ],
    "xss": ["xss", "reflected-xss", "stored-xss", "dom-xss"],
    "auth": ["auth", "authentication", "authorization", "session"],
    "crypto": ["crypto", "encryption", "hashing", "tls", "ssl"],
    "secrets": ["secrets", "hardcoded", "password", "api-key", "token"],
    "deserialization": ["deserialization", "pickle", "yaml-load", "eval"],
    "path-traversal": ["path-traversal", "directory-traversal", "lfi", "rfi"],
    "ssrf": ["ssrf", "server-side-request"],
    "xxe": ["xxe", "xml-external-entity"],
    "ssti": ["ssti", "template-injection"],
}


def get_rule_category(rule_id: str) -> str:
    """Get the category for a Semgrep rule ID."""
    rule_lower = rule_id.lower()
    for category, keywords in SEMGREP_CATEGORIES.items():
        if any(kw in rule_lower for kw in keywords):
            return category
    return "security"

