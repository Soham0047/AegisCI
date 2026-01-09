"""
Guardian Security Scanners

Comprehensive security scanning with multiple detection methods:
- bandit_scanner: Python security analysis (ALL Bandit rules)
- semgrep_scanner: Multi-language security patterns (OWASP, secrets, etc.)
- secrets_scanner: Hardcoded credentials and API key detection
- pattern_scanner: Dangerous code pattern detection
- dependency_scanner: Known vulnerable dependency detection
"""

from guardian.scanners.bandit_scanner import (
    BANDIT_CATEGORIES,
    get_rule_category as get_bandit_category,
    run_bandit,
    run_bandit_recursive,
)
from guardian.scanners.dependency_scanner import (
    run_dependency_scanner,
    scan_directory as scan_dependencies,
    scan_package_json,
    scan_pyproject_toml,
    scan_requirements_txt,
)
from guardian.scanners.pattern_scanner import (
    run_comprehensive_scan,
    run_pattern_scanner,
)
from guardian.scanners.secrets_scanner import (
    run_secrets_scanner,
    scan_file as scan_file_for_secrets,
)
from guardian.scanners.semgrep_scanner import (
    DEFAULT_RULESETS,
    SEMGREP_RULESETS,
    get_rule_category as get_semgrep_category,
    run_semgrep,
    run_semgrep_comprehensive,
    run_semgrep_owasp,
    run_semgrep_secrets,
)

__all__ = [
    # Bandit
    "run_bandit",
    "run_bandit_recursive",
    "BANDIT_CATEGORIES",
    "get_bandit_category",
    # Semgrep
    "run_semgrep",
    "run_semgrep_comprehensive",
    "run_semgrep_owasp",
    "run_semgrep_secrets",
    "SEMGREP_RULESETS",
    "DEFAULT_RULESETS",
    "get_semgrep_category",
    # Secrets
    "run_secrets_scanner",
    "scan_file_for_secrets",
    # Patterns
    "run_pattern_scanner",
    "run_comprehensive_scan",
    # Dependencies
    "run_dependency_scanner",
    "scan_dependencies",
    "scan_requirements_txt",
    "scan_package_json",
    "scan_pyproject_toml",
]

