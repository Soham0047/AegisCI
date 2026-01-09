"""
Secrets Scanner - Detects hardcoded credentials, API keys, and tokens.

This scanner uses regex patterns to detect various types of secrets:
- API keys (AWS, GCP, Azure, OpenAI, GitHub, etc.)
- Passwords and tokens
- Private keys (RSA, DSA, EC, etc.)
- Database connection strings
- OAuth tokens and JWTs
- Cloud provider credentials
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class SecretPattern:
    """A pattern for detecting a specific type of secret."""
    name: str
    pattern: re.Pattern[str]
    severity: str  # critical, high, medium, low
    category: str
    description: str
    false_positive_patterns: list[re.Pattern[str]] | None = None


# Comprehensive secret detection patterns
SECRET_PATTERNS: list[SecretPattern] = [
    # AWS
    SecretPattern(
        name="AWS Access Key ID",
        pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
        severity="critical",
        category="cloud",
        description="AWS Access Key ID - grants access to AWS services",
    ),
    SecretPattern(
        name="AWS Secret Access Key",
        pattern=re.compile(r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\s:=]+['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        severity="critical",
        category="cloud",
        description="AWS Secret Access Key - provides full AWS API access",
    ),
    SecretPattern(
        name="AWS MWS Auth Token",
        pattern=re.compile(r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
        severity="high",
        category="cloud",
        description="Amazon MWS Auth Token",
    ),
    
    # Google Cloud
    SecretPattern(
        name="Google API Key",
        pattern=re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        severity="high",
        category="cloud",
        description="Google Cloud API Key",
    ),
    SecretPattern(
        name="Google OAuth Token",
        pattern=re.compile(r"ya29\.[0-9A-Za-z\-_]+"),
        severity="high",
        category="cloud",
        description="Google OAuth Access Token",
    ),
    SecretPattern(
        name="Google Cloud Service Account",
        pattern=re.compile(r'"type":\s*"service_account"'),
        severity="critical",
        category="cloud",
        description="Google Cloud Service Account JSON key file",
    ),
    
    # Azure
    SecretPattern(
        name="Azure Storage Key",
        pattern=re.compile(r"(?i)azure[_\-]?storage[_\-]?key[\s:=]+['\"]?([A-Za-z0-9/+=]{88})['\"]?"),
        severity="critical",
        category="cloud",
        description="Azure Storage Account Key",
    ),
    SecretPattern(
        name="Azure AD Client Secret",
        pattern=re.compile(r"(?i)client[_\-]?secret[\s:=]+['\"]?([A-Za-z0-9\-_.~]{34,})['\"]?"),
        severity="high",
        category="cloud",
        description="Azure AD Client Secret",
    ),
    
    # GitHub
    SecretPattern(
        name="GitHub Personal Access Token",
        pattern=re.compile(r"ghp_[A-Za-z0-9]{36}"),
        severity="critical",
        category="vcs",
        description="GitHub Personal Access Token - grants repository access",
    ),
    SecretPattern(
        name="GitHub OAuth Token",
        pattern=re.compile(r"gho_[A-Za-z0-9]{36}"),
        severity="critical",
        category="vcs",
        description="GitHub OAuth Access Token",
    ),
    SecretPattern(
        name="GitHub App Token",
        pattern=re.compile(r"ghu_[A-Za-z0-9]{36}"),
        severity="critical",
        category="vcs",
        description="GitHub App User Token",
    ),
    SecretPattern(
        name="GitHub Fine-grained PAT",
        pattern=re.compile(r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}"),
        severity="critical",
        category="vcs",
        description="GitHub Fine-grained Personal Access Token",
    ),
    
    # GitLab
    SecretPattern(
        name="GitLab Personal Access Token",
        pattern=re.compile(r"glpat-[A-Za-z0-9\-]{20}"),
        severity="critical",
        category="vcs",
        description="GitLab Personal Access Token",
    ),
    
    # Slack
    SecretPattern(
        name="Slack Bot Token",
        pattern=re.compile(r"xoxb-[0-9]{11,13}-[0-9]{11,13}-[A-Za-z0-9]{24}"),
        severity="high",
        category="messaging",
        description="Slack Bot Token - can post messages and access data",
    ),
    SecretPattern(
        name="Slack User Token",
        pattern=re.compile(r"xoxp-[0-9]{11,13}-[0-9]{11,13}-[0-9]{11,13}-[A-Za-z0-9]{32}"),
        severity="high",
        category="messaging",
        description="Slack User Token",
    ),
    SecretPattern(
        name="Slack Webhook URL",
        pattern=re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
        severity="medium",
        category="messaging",
        description="Slack Webhook URL",
    ),
    
    # OpenAI
    SecretPattern(
        name="OpenAI API Key",
        pattern=re.compile(r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"),
        severity="critical",
        category="ai",
        description="OpenAI API Key - grants access to GPT models",
    ),
    SecretPattern(
        name="OpenAI API Key (new format)",
        pattern=re.compile(r"sk-proj-[A-Za-z0-9\-_]{48,}"),
        severity="critical",
        category="ai",
        description="OpenAI Project API Key",
    ),
    
    # Anthropic
    SecretPattern(
        name="Anthropic API Key",
        pattern=re.compile(r"sk-ant-[A-Za-z0-9\-_]{95,}"),
        severity="critical",
        category="ai",
        description="Anthropic Claude API Key",
    ),
    
    # Stripe
    SecretPattern(
        name="Stripe API Key",
        pattern=re.compile(r"sk_live_[0-9a-zA-Z]{24}"),
        severity="critical",
        category="payment",
        description="Stripe Live API Key - can process real payments",
    ),
    SecretPattern(
        name="Stripe Test Key",
        pattern=re.compile(r"sk_test_[0-9a-zA-Z]{24}"),
        severity="medium",
        category="payment",
        description="Stripe Test API Key",
    ),
    SecretPattern(
        name="Stripe Restricted Key",
        pattern=re.compile(r"rk_live_[0-9a-zA-Z]{24}"),
        severity="critical",
        category="payment",
        description="Stripe Restricted Live API Key",
    ),
    
    # Twilio
    SecretPattern(
        name="Twilio API Key",
        pattern=re.compile(r"SK[0-9a-fA-F]{32}"),
        severity="high",
        category="messaging",
        description="Twilio API Key",
    ),
    SecretPattern(
        name="Twilio Account SID",
        pattern=re.compile(r"AC[0-9a-fA-F]{32}"),
        severity="medium",
        category="messaging",
        description="Twilio Account SID",
    ),
    
    # SendGrid
    SecretPattern(
        name="SendGrid API Key",
        pattern=re.compile(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"),
        severity="high",
        category="messaging",
        description="SendGrid API Key",
    ),
    
    # Database connection strings
    SecretPattern(
        name="PostgreSQL Connection String",
        pattern=re.compile(r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+/\w+"),
        severity="critical",
        category="database",
        description="PostgreSQL connection string with credentials",
    ),
    SecretPattern(
        name="MySQL Connection String",
        pattern=re.compile(r"mysql://[^:]+:[^@]+@[^/]+/\w+"),
        severity="critical",
        category="database",
        description="MySQL connection string with credentials",
    ),
    SecretPattern(
        name="MongoDB Connection String",
        pattern=re.compile(r"mongodb(\+srv)?://[^:]+:[^@]+@[^/]+"),
        severity="critical",
        category="database",
        description="MongoDB connection string with credentials",
    ),
    SecretPattern(
        name="Redis Connection String",
        pattern=re.compile(r"redis://:[^@]+@[^/]+"),
        severity="high",
        category="database",
        description="Redis connection string with password",
    ),
    
    # Private keys
    SecretPattern(
        name="RSA Private Key",
        pattern=re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
        severity="critical",
        category="crypto",
        description="RSA Private Key - used for authentication and encryption",
    ),
    SecretPattern(
        name="DSA Private Key",
        pattern=re.compile(r"-----BEGIN DSA PRIVATE KEY-----"),
        severity="critical",
        category="crypto",
        description="DSA Private Key",
    ),
    SecretPattern(
        name="EC Private Key",
        pattern=re.compile(r"-----BEGIN EC PRIVATE KEY-----"),
        severity="critical",
        category="crypto",
        description="Elliptic Curve Private Key",
    ),
    SecretPattern(
        name="OpenSSH Private Key",
        pattern=re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
        severity="critical",
        category="crypto",
        description="OpenSSH Private Key",
    ),
    SecretPattern(
        name="PGP Private Key",
        pattern=re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        severity="critical",
        category="crypto",
        description="PGP Private Key Block",
    ),
    
    # JWT
    SecretPattern(
        name="JSON Web Token",
        pattern=re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"),
        severity="high",
        category="auth",
        description="JSON Web Token - may contain sensitive claims",
    ),
    
    # Generic patterns
    SecretPattern(
        name="Generic API Key",
        pattern=re.compile(r"(?i)(api[_\-]?key|apikey)[\s:=]+['\"]?([A-Za-z0-9\-_]{20,})['\"]?"),
        severity="medium",
        category="generic",
        description="Generic API Key pattern",
    ),
    SecretPattern(
        name="Generic Secret",
        pattern=re.compile(r"(?i)(secret|password|passwd|pwd)[\s:=]+['\"]?([A-Za-z0-9!@#$%^&*\-_]{8,})['\"]?"),
        severity="high",
        category="generic",
        description="Generic secret or password",
        false_positive_patterns=[
            re.compile(r"(?i)(example|sample|test|dummy|placeholder|your[_\-]?|my[_\-]?)"),
            re.compile(r"(?i)\$\{.*\}"),  # Environment variable placeholders
            re.compile(r"(?i)%\(.*\)s"),  # Python string formatting
        ],
    ),
    SecretPattern(
        name="Bearer Token",
        pattern=re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_\.]+"),
        severity="high",
        category="auth",
        description="Bearer authentication token",
    ),
    SecretPattern(
        name="Basic Auth Header",
        pattern=re.compile(r"(?i)basic\s+[A-Za-z0-9+/=]{20,}"),
        severity="high",
        category="auth",
        description="Basic authentication header (base64 encoded credentials)",
    ),
    
    # NPM
    SecretPattern(
        name="NPM Token",
        pattern=re.compile(r"npm_[A-Za-z0-9]{36}"),
        severity="high",
        category="package",
        description="NPM Access Token",
    ),
    
    # PyPI
    SecretPattern(
        name="PyPI Token",
        pattern=re.compile(r"pypi-[A-Za-z0-9\-_]{50,}"),
        severity="high",
        category="package",
        description="PyPI API Token",
    ),
    
    # Heroku
    SecretPattern(
        name="Heroku API Key",
        pattern=re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
        severity="medium",
        category="cloud",
        description="Heroku API Key (UUID format)",
    ),
    
    # DigitalOcean
    SecretPattern(
        name="DigitalOcean Token",
        pattern=re.compile(r"dop_v1_[a-f0-9]{64}"),
        severity="high",
        category="cloud",
        description="DigitalOcean Personal Access Token",
    ),
    
    # Mailchimp
    SecretPattern(
        name="Mailchimp API Key",
        pattern=re.compile(r"[0-9a-f]{32}-us[0-9]{1,2}"),
        severity="medium",
        category="messaging",
        description="Mailchimp API Key",
    ),
    
    # Discord
    SecretPattern(
        name="Discord Bot Token",
        pattern=re.compile(r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}"),
        severity="high",
        category="messaging",
        description="Discord Bot Token",
    ),
    SecretPattern(
        name="Discord Webhook",
        pattern=re.compile(r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+"),
        severity="medium",
        category="messaging",
        description="Discord Webhook URL",
    ),
]

# Files to skip during scanning
SKIP_EXTENSIONS = {
    ".min.js", ".min.css", ".map", ".lock",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot",
    ".zip", ".tar", ".gz", ".rar",
    ".pdf", ".doc", ".docx",
}

SKIP_DIRECTORIES = {
    "node_modules", ".git", ".svn", ".hg",
    "__pycache__", ".pytest_cache", ".mypy_cache",
    "dist", "build", ".next", ".nuxt",
    "vendor", "venv", ".venv", "env",
}


@dataclass
class SecretFinding:
    """A detected secret finding."""
    filepath: str
    line_number: int
    column: int
    secret_type: str
    severity: str
    category: str
    description: str
    matched_text: str
    line_content: str


def scan_file(filepath: str | Path) -> list[SecretFinding]:
    """Scan a single file for secrets."""
    findings: list[SecretFinding] = []
    path = Path(filepath)
    
    # Skip binary and unreadable files
    if path.suffix.lower() in SKIP_EXTENSIONS:
        return findings
    
    # Skip directories in skip list
    for skip_dir in SKIP_DIRECTORIES:
        if skip_dir in path.parts:
            return findings
    
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings
    
    lines = content.split("\n")
    
    for line_num, line in enumerate(lines, 1):
        for pattern in SECRET_PATTERNS:
            for match in pattern.pattern.finditer(line):
                # Check for false positives
                is_false_positive = False
                if pattern.false_positive_patterns:
                    matched_text = match.group(0)
                    for fp_pattern in pattern.false_positive_patterns:
                        if fp_pattern.search(matched_text) or fp_pattern.search(line):
                            is_false_positive = True
                            break
                
                if not is_false_positive:
                    findings.append(SecretFinding(
                        filepath=str(path),
                        line_number=line_num,
                        column=match.start(),
                        secret_type=pattern.name,
                        severity=pattern.severity,
                        category=pattern.category,
                        description=pattern.description,
                        matched_text=_redact_secret(match.group(0)),
                        line_content=_redact_line(line, match),
                    ))
    
    return findings


def scan_files(files: list[str]) -> dict[str, Any]:
    """Scan multiple files for secrets."""
    all_findings: list[SecretFinding] = []
    scanned_files = 0
    errors: list[str] = []
    
    for filepath in files:
        try:
            findings = scan_file(filepath)
            all_findings.extend(findings)
            scanned_files += 1
        except Exception as e:
            errors.append(f"Error scanning {filepath}: {e}")
    
    # Convert to dict format matching other scanners
    results = []
    for finding in all_findings:
        results.append({
            "check_id": f"secrets/{finding.secret_type.lower().replace(' ', '-')}",
            "check_name": finding.secret_type,
            "path": finding.filepath,
            "start": {"line": finding.line_number, "col": finding.column},
            "end": {"line": finding.line_number, "col": finding.column + len(finding.matched_text)},
            "extra": {
                "message": finding.description,
                "severity": finding.severity.upper(),
                "metadata": {
                    "category": finding.category,
                    "owasp": "A02:2021",  # Cryptographic Failures
                    "cwe": "CWE-798",  # Use of Hard-coded Credentials
                },
            },
        })
    
    return {
        "results": results,
        "errors": errors,
        "scanner": "secrets",
        "version": "1.0.0",
        "paths": {
            "scanned": files,
            "findings_count": len(all_findings),
        },
        "metrics": {
            "total_files": scanned_files,
            "total_findings": len(all_findings),
            "by_severity": _count_by_severity(all_findings),
            "by_category": _count_by_category(all_findings),
        },
    }


def run_secrets_scanner(files: list[str]) -> dict[str, Any]:
    """Run the secrets scanner on provided files."""
    return scan_files(files)


def _redact_secret(text: str, visible_chars: int = 4) -> str:
    """Redact a secret, keeping only first few characters visible."""
    if len(text) <= visible_chars * 2:
        return "*" * len(text)
    return text[:visible_chars] + "*" * (len(text) - visible_chars * 2) + text[-visible_chars:]


def _redact_line(line: str, match: re.Match[str]) -> str:
    """Redact the secret portion of a line."""
    start, end = match.start(), match.end()
    redacted = _redact_secret(match.group(0))
    return line[:start] + redacted + line[end:]


def _count_by_severity(findings: list[SecretFinding]) -> dict[str, int]:
    """Count findings by severity."""
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def _count_by_category(findings: list[SecretFinding]) -> dict[str, int]:
    """Count findings by category."""
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.category] = counts.get(finding.category, 0) + 1
    return counts
