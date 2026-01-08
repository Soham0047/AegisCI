#!/usr/bin/env python3
"""
Automated gold labeling script.
Uses heuristics based on rule IDs, severity, and code context to label findings.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

import typer

from guardian.data.gold_schema import (
    FindingRef,
    GoldLabel,
    SpanRef,
)
from guardian.data.label_cli import (
    _label_key,
    generate_selection,
    load_labeled_keys,
    load_selected_items,
    parse_inputs,
)

app = typer.Typer(add_completion=False)


# Rule ID patterns -> (category, fix_type, likely_verdict)
# More specific patterns should come before generic ones
RULE_PATTERNS: list[tuple[str, str, str, str]] = [
    # SQL Injection
    (r"sql[-_]?inject|sqli|B608", "injection.sql", "parameterize_query", "TP"),
    (r"hardcoded[-_]?sql|string[-_]?concat.*sql", "injection.sql", "parameterize_query", "TP"),
    (r"nosql[-_]?inject|mongo.*inject", "injection.nosql", "parameterize_query", "TP"),
    # Command Injection
    (
        r"command[-_]?inject|os[-_]?command|B602|B603|B604|B605|B606|B607",
        "injection.command",
        "use_subprocess_list",
        "TP",
    ),
    (r"shell[-_]?inject|subprocess.*shell", "injection.command", "avoid_shell_execution", "TP"),
    (r"start[-_]?process|spawn|popen", "injection.command", "use_subprocess_list", "TP"),
    # XSS
    (
        r"xss|cross[-_]?site[-_]?script|innerhtml|dangerouslysetinnerhtml",
        "injection.xss",
        "escape_output",
        "TP",
    ),
    (r"reflected[-_]?xss|stored[-_]?xss|dom[-_]?xss", "injection.xss", "escape_output", "TP"),
    (r"document\.write|\.html\(|v-html", "injection.xss", "escape_output", "TP"),
    # Template Injection
    (r"template[-_]?inject|ssti|jinja.*inject", "injection.template", "sanitize_input", "TP"),
    (r"format[-_]?string|f[-_]?string.*user", "injection.template", "sanitize_input", "TP"),
    # XXE
    (
        r"xxe|xml[-_]?external|xml[-_]?entity|B314|B318|B320",
        "injection.xxe",
        "use_safe_parser",
        "TP",
    ),
    (r"dtd|doctype.*system", "injection.xxe", "use_safe_parser", "TP"),
    # LDAP Injection
    (r"ldap[-_]?inject", "injection.ldap", "sanitize_input", "TP"),
    # XPath Injection
    (r"xpath[-_]?inject", "injection.xpath", "parameterize_query", "TP"),
    # Header Injection
    (
        r"header[-_]?inject|crlf[-_]?inject|response[-_]?split",
        "injection.header",
        "sanitize_input",
        "TP",
    ),
    # Log Injection
    (r"log[-_]?inject|log[-_]?forg", "injection.log", "sanitize_input", "TP"),
    # Regex DoS
    (r"redos|regex[-_]?dos|catastrophic[-_]?backtrack", "dos.regex", "sanitize_input", "TP"),
    # Crypto - Weak Algorithm
    (r"md5|sha1(?!.)|B303|B304|weak[-_]?hash", "crypto.weak_algorithm", "upgrade_algorithm", "TP"),
    (r"des|rc4|blowfish|3des|arcfour", "crypto.weak_algorithm", "upgrade_algorithm", "TP"),
    # Crypto - Weak Key
    (r"weak[-_]?key|short[-_]?key|key[-_]?size|B505", "crypto.weak_key", "use_strong_key", "TP"),
    (r"rsa.*1024|rsa.*512", "crypto.weak_key", "use_strong_key", "TP"),
    # Crypto - Weak Random
    (
        r"random|B311|math\.random|insecure[-_]?random",
        "crypto.weak_random",
        "use_secure_random",
        "TP",
    ),
    (r"pseudo[-_]?random|prng|seed", "crypto.weak_random", "use_secure_random", "TP"),
    # Crypto - Hardcoded Key
    (
        r"hardcoded[-_]?key|hardcoded[-_]?iv|static[-_]?key|B106",
        "crypto.hardcoded_key",
        "use_secret_manager",
        "TP",
    ),
    # Crypto - TLS/SSL
    (
        r"ssl[-_]?verify|tls[-_]?verify|no[-_]?verify|B501|B502|B503",
        "crypto.insecure_tls",
        "enable_certificate_validation",
        "TP",
    ),
    (r"sslv2|sslv3|tls[-_]?1\.0|tls[-_]?1\.1", "crypto.insecure_tls", "use_tls_1_3", "TP"),
    (
        r"verify[-_]?false|verify[-_]?=[-_]?false|insecure[-_]?ssl",
        "crypto.certificate_validation",
        "enable_certificate_validation",
        "TP",
    ),
    # Auth - CSRF
    (r"csrf|cross[-_]?site[-_]?request[-_]?forg", "auth.csrf", "add_csrf_protection", "TP"),
    # Auth - CORS
    (
        r"cors|access[-_]?control[-_]?allow|origin.*\*",
        "auth.cors_misconfiguration",
        "configure_cors_properly",
        "TP",
    ),
    # Auth - JWT
    (
        r"jwt|json[-_]?web[-_]?token|algorithm.*none|alg.*none",
        "auth.jwt_vulnerability",
        "use_safe_api",
        "TP",
    ),
    # Auth - Session
    (r"session[-_]?fix|session[-_]?hijack", "auth.session_fixation", "secure_session_config", "TP"),
    (
        r"session[-_]?expir|session[-_]?timeout",
        "auth.session_expiration",
        "secure_session_config",
        "TP",
    ),
    (
        r"insecure[-_]?cookie|cookie.*secure|httponly",
        "auth.insecure_cookie",
        "use_secure_cookie_flags",
        "TP",
    ),
    # Auth - General
    (
        r"broken[-_]?auth|auth[-_]?bypass|authentication[-_]?fail",
        "auth.broken_authentication",
        "add_auth_check",
        "TP",
    ),
    (
        r"missing[-_]?auth|no[-_]?auth|unauthenticated",
        "auth.missing_authentication",
        "add_auth_check",
        "TP",
    ),
    (r"idor|insecure[-_]?direct[-_]?object", "auth.idor", "add_authorization_check", "TP"),
    (r"privilege[-_]?escal|privesc", "auth.privilege_escalation", "add_authorization_check", "TP"),
    # Secrets - Specific Types
    (
        r"hardcoded[-_]?password|password.*=.*['\"]|B105|B107",
        "secrets.hardcoded_password",
        "use_environment_variable",
        "TP",
    ),
    (r"api[-_]?key.*=.*['\"]|apikey|B104", "secrets.hardcoded_api_key", "use_secret_manager", "TP"),
    (
        r"access[-_]?token|bearer[-_]?token|oauth[-_]?token",
        "secrets.hardcoded_token",
        "use_secret_manager",
        "TP",
    ),
    (
        r"private[-_]?key|-----BEGIN.*KEY",
        "secrets.hardcoded_private_key",
        "use_secret_manager",
        "TP",
    ),
    (
        r"secret.*log|password.*log|credential.*log",
        "secrets.exposed_in_log",
        "sanitize_output",
        "TP",
    ),
    (r"secret|credential|B108", "secrets.exposure", "rotate_secret", "TP"),
    # Data Exposure
    (r"sensitive[-_]?data|pii|personal[-_]?info", "data.pii_exposure", "encrypt_at_rest", "TP"),
    (r"debug.*true|debug.*enabled|B201", "data.debug_enabled", "disable_debug_mode", "TP"),
    (
        r"stack[-_]?trace|error[-_]?detail|verbose[-_]?error",
        "data.error_disclosure",
        "sanitize_error_messages",
        "TP",
    ),
    # Deserialization - Specific Types
    (r"pickle|unpickle|B301|B302", "deserialization.unsafe_pickle", "use_safe_deserializer", "TP"),
    (r"yaml\.load|yaml\.unsafe|B506", "deserialization.unsafe_yaml", "use_safe_deserializer", "TP"),
    (r"marshal|unmarshal", "deserialization.unsafe", "use_safe_deserializer", "TP"),
    (
        r"prototype[-_]?pollut|__proto__|constructor.*prototype",
        "deserialization.prototype_pollution",
        "use_safe_api",
        "TP",
    ),
    # Path Traversal & File
    (
        r"path[-_]?travers|directory[-_]?travers|\.\.\/|B108",
        "path.traversal",
        "canonicalize_path",
        "TP",
    ),
    (r"local[-_]?file[-_]?inclu|lfi", "path.local_file_inclusion", "validate_path", "TP"),
    (r"remote[-_]?file[-_]?inclu|rfi", "path.remote_file_inclusion", "validate_path", "TP"),
    (
        r"arbitrary[-_]?file[-_]?write|file[-_]?overwrite",
        "file.arbitrary_write",
        "restrict_file_access",
        "TP",
    ),
    (
        r"arbitrary[-_]?file[-_]?read|file[-_]?disclosure",
        "file.arbitrary_read",
        "restrict_file_access",
        "TP",
    ),
    (r"file[-_]?upload|unrestricted[-_]?upload", "file.unsafe_upload", "validate_file_type", "TP"),
    (r"symlink|symbolic[-_]?link", "file.symlink_attack", "canonicalize_path", "TP"),
    # SSRF
    (r"ssrf|server[-_]?side[-_]?request", "ssrf", "whitelist_input", "TP"),
    (r"url[-_]?fetch|request[-_]?forgery", "ssrf", "whitelist_input", "TP"),
    (
        r"cloud[-_]?metadata|169\.254\.169\.254|metadata[-_]?service",
        "ssrf.cloud_metadata",
        "whitelist_input",
        "TP",
    ),
    # Open Redirect
    (
        r"open[-_]?redirect|url[-_]?redirect|unvalidated[-_]?redirect",
        "open_redirect",
        "whitelist_input",
        "TP",
    ),
    # Unsafe exec/eval
    (r"eval\(|B307", "unsafe.eval", "remove_eval_exec", "TP"),
    (r"exec\(|B102", "unsafe.exec", "remove_eval_exec", "TP"),
    (
        r"code[-_]?exec|dynamic[-_]?code|compile\(",
        "unsafe.code_injection",
        "remove_eval_exec",
        "TP",
    ),
    (r"dynamic[-_]?import|__import__|importlib", "unsafe.dynamic_import", "use_safe_api", "TP"),
    (r"reflection|getattr.*user|setattr.*user", "unsafe.reflection", "sanitize_input", "TP"),
    # DoS
    (r"billion[-_]?laughs|xml[-_]?bomb", "dos.xml_bomb", "use_safe_parser", "TP"),
    (r"zip[-_]?bomb|decompression[-_]?bomb", "dos.zip_bomb", "limit_file_size", "TP"),
    (
        r"resource[-_]?exhaust|memory[-_]?exhaust",
        "dos.resource_exhaustion",
        "add_resource_limits",
        "TP",
    ),
    (r"infinite[-_]?loop|endless[-_]?loop", "dos.infinite_loop", "implement_timeout", "TP"),
    (
        r"uncontrolled[-_]?recurs|stack[-_]?overflow",
        "dos.uncontrolled_recursion",
        "add_resource_limits",
        "TP",
    ),
    # Dependency vulnerabilities
    (
        r"cve[-_]?\d+|known[-_]?vuln|vulnerable[-_]?dep",
        "dependency.known_vuln",
        "upgrade_dependency",
        "TP",
    ),
    (r"outdated|deprecated[-_]?version", "dependency.outdated", "upgrade_dependency", "TP"),
    # Memory issues (for languages like C/C++ detected via semgrep)
    (r"buffer[-_]?overflow|stack[-_]?buffer", "memory.buffer_overflow", "use_safe_api", "TP"),
    (
        r"use[-_]?after[-_]?free|dangling[-_]?pointer",
        "memory.use_after_free",
        "refactor_logic",
        "TP",
    ),
    (r"null[-_]?pointer|nullptr|null[-_]?deref", "memory.null_pointer", "add_error_handling", "TP"),
    (r"integer[-_]?overflow|int[-_]?overflow", "memory.integer_overflow", "validate_input", "TP"),
    (r"format[-_]?string[-_]?vuln", "memory.format_string", "use_safe_api", "TP"),
    # Configuration issues
    (
        r"insecure[-_]?default|default[-_]?config",
        "config.insecure_default",
        "restrict_permissions",
        "TP",
    ),
    (r"admin[-_]?expos|management[-_]?interface", "config.exposed_admin", "add_auth_check", "TP"),
    (
        r"missing[-_]?security[-_]?header|x-frame|x-content",
        "config.missing_security_headers",
        "configure_security_headers",
        "TP",
    ),
    # Race conditions
    (
        r"race[-_]?condition|toctou|time[-_]?of[-_]?check",
        "logic.race_condition",
        "refactor_logic",
        "TP",
    ),
    # Catch-all patterns (should be at the end)
    (r"B\d{3}", "misc.other", "unknown", "TP"),  # Bandit rules (fallback)
]

# ============================================================================
# ENHANCED FP/TP DETECTION PATTERNS
# ============================================================================

# False positive patterns - files/paths that indicate non-production code
FP_PATH_PATTERNS: list[str] = [
    # Test files and directories
    r"test[-_]?file|test[-_]?case|mock|fixture",
    r"\.test\.|_test\.|test_|tests/|__tests__/",
    r"spec\.|\.spec\.|specs/",
    r"pytest|unittest|jest|mocha|cypress",
    # Example, demo, and sample code
    r"example|demo|sample|tutorial|playground",
    r"documentation|readme|docs/",
    # Vendor and third-party code (not our responsibility to fix)
    r"vendor/|vendors/|third[-_]?party|external/",
    r"node_modules/|bower_components/",
    r"static/ckeditor|ckeditor/|tinymce/|codemirror/",
    r"jquery|bootstrap|lodash|moment\.js",
    r"\.min\.js$|\.bundle\.js$",
    # Generated/build artifacts
    r"dist/|build/|\.next/|__pycache__/",
    r"\.generated\.|auto[-_]?generated",
    # Config and setup files (usually intentional)
    r"conftest\.py|setup\.py|setup\.cfg",
    r"webpack\.config|vite\.config|next\.config",
    # Migration and seed files (often have intentional "insecure" patterns)
    r"migrations?/|seeds?/|fixtures/",
]

# Patterns in file content/code that indicate FP
FP_CODE_PATTERNS: list[str] = [
    r"# nosec|# noqa|# pragma: no cover",
    r"// eslint-disable|/\* eslint-disable",
    r"@pytest\.|def test_|it\(.*should|describe\(",
    r"mock\.|Mock\(|patch\(|stub\(",
    r"assert[A-Z]|self\.assert|expect\(",
]

# Rule-specific FP patterns (certain rules in certain contexts are FP)
RULE_FP_OVERRIDES: dict[str, list[str]] = {
    # B101: assert statements - FP in test files, TP in production
    "B101": [r"test|spec|pytest|unittest"],
    # B110: try-except-pass - often acceptable in specific contexts
    "B110": [r"optional|fallback|ignore|skip"],
    # B311: random - FP for non-crypto uses (shuffling, sampling, etc.)
    "B311": [r"shuffle|sample|choice|display|ui|color|game|demo"],
    # innerhtml in vendor libraries
    "innerhtml": [r"ckeditor|tinymce|jquery|vendor|static/.*\.js"],
    # B404: subprocess import - just an import, not a vulnerability
    "B404": [r".*"],  # Always FP - importing subprocess isn't a vuln
    # B105/B106/B107: hardcoded passwords - FP in test/config contexts
    "B105|B106|B107": [r"test|example|placeholder|dummy|sample|config"],
}

# Patterns that indicate definite TRUE POSITIVE (high confidence)
TP_PATTERNS: list[tuple[str, str]] = [
    # Direct user input to dangerous sinks
    (r"request\.(get|post|args|form|data|json)", "User input from web request"),
    (r"sys\.argv|input\(|raw_input", "User input from CLI/stdin"),
    (r"os\.environ\.get.*\+.*sql|query", "Env var in SQL without parameterization"),
    # Dangerous function calls with user input
    (r"eval\s*\(\s*request|exec\s*\(\s*request", "eval/exec with request data"),
    (r"subprocess.*shell\s*=\s*True.*request", "Shell command with user input"),
    (r"pickle\.loads?\s*\(\s*request", "Pickle with user input"),
    # Hardcoded secrets that look real (not placeholders)
    (
        r"(password|secret|key|token)\s*=\s*['\"][a-zA-Z0-9]{16,}['\"]",
        "Hardcoded secret (long random string)",
    ),
    (r"-----BEGIN.*PRIVATE KEY-----", "Hardcoded private key"),
    (r"(api[_-]?key|access[_-]?token)\s*=\s*['\"][^'\"]+['\"]", "Hardcoded API key/token"),
    # SQL injection patterns
    (
        r"execute\s*\([^)]*%s|execute\s*\([^)]*\+|execute\s*\(.*\.format",
        "SQL with string formatting",
    ),
    (
        r"cursor\.execute\s*\(\s*f['\"]|cursor\.execute\s*\([^,]+\+",
        "SQL with f-string or concatenation",
    ),
    # XSS patterns in actual app code (not vendor)
    (r"innerHTML\s*=.*req|innerHTML\s*=.*user|innerHTML\s*=.*param", "innerHTML with user input"),
]

# Severity/Confidence adjustments
SEVERITY_WEIGHTS = {
    "CRITICAL": 1.0,
    "HIGH": 0.9,
    "MEDIUM": 0.7,
    "LOW": 0.4,
    "WARNING": 0.6,
    "INFO": 0.2,
    "INFORMATION": 0.2,
}

CONFIDENCE_WEIGHTS = {
    "HIGH": 1.0,
    "MEDIUM": 0.7,
    "LOW": 0.4,
}

# Legacy pattern for backwards compatibility
FP_PATTERNS = FP_PATH_PATTERNS  # Alias for old code

# Patterns that indicate UNCERTAIN
UNCERTAIN_PATTERNS: list[str] = [
    r"generic|informational|info[-_]?only",
    r"potential|possible|may[-_]?be",
]


def infer_category(rule_id: str, message: str) -> str:
    """Infer category from rule_id and message."""
    combined = f"{rule_id} {message}".lower()

    for pattern, category, _, _ in RULE_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            return category

    return "misc.other"


def infer_fix_type(rule_id: str, message: str, category: str) -> str:
    """Infer fix type from rule_id, message, and category."""
    combined = f"{rule_id} {message}".lower()

    for pattern, cat, fix_type, _ in RULE_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            return fix_type

    # Fallback based on category
    category_fix_map = {
        # Injection categories
        "injection.sql": "parameterize_query",
        "injection.nosql": "parameterize_query",
        "injection.command": "use_subprocess_list",
        "injection.xss": "escape_output",
        "injection.xxe": "use_safe_parser",
        "injection.ldap": "sanitize_input",
        "injection.xpath": "parameterize_query",
        "injection.template": "sanitize_input",
        "injection.header": "sanitize_input",
        "injection.log": "sanitize_input",
        "injection.email": "sanitize_input",
        "injection.regex": "sanitize_input",
        # Crypto categories
        "crypto.weak_algorithm": "upgrade_algorithm",
        "crypto.weak_key": "use_strong_key",
        "crypto.weak_random": "use_secure_random",
        "crypto.insecure_mode": "use_safe_api",
        "crypto.missing_integrity": "add_integrity_check",
        "crypto.hardcoded_key": "use_secret_manager",
        "crypto.insecure_tls": "use_tls_1_3",
        "crypto.certificate_validation": "enable_certificate_validation",
        "crypto.insecure": "use_safe_api",
        # Auth categories
        "auth.broken_authentication": "add_auth_check",
        "auth.missing_authentication": "add_auth_check",
        "auth.weak_password": "use_safe_api",
        "auth.session_fixation": "secure_session_config",
        "auth.session_expiration": "secure_session_config",
        "auth.insecure_cookie": "use_secure_cookie_flags",
        "auth.csrf": "add_csrf_protection",
        "auth.cors_misconfiguration": "configure_cors_properly",
        "auth.jwt_vulnerability": "use_safe_api",
        "auth.oauth_misconfiguration": "use_safe_api",
        "auth.privilege_escalation": "add_authorization_check",
        "auth.idor": "add_authorization_check",
        "auth.session": "add_auth_check",
        # Secrets categories
        "secrets.hardcoded_password": "use_environment_variable",
        "secrets.hardcoded_api_key": "use_secret_manager",
        "secrets.hardcoded_token": "use_secret_manager",
        "secrets.hardcoded_private_key": "use_secret_manager",
        "secrets.exposed_in_log": "sanitize_output",
        "secrets.exposed_in_error": "sanitize_error_messages",
        "secrets.insecure_storage": "encrypt_at_rest",
        "secrets.exposure": "rotate_secret",
        # Data exposure categories
        "data.sensitive_exposure": "encrypt_at_rest",
        "data.pii_exposure": "encrypt_at_rest",
        "data.insufficient_encryption": "use_safe_api",
        "data.insecure_transmission": "use_tls_1_3",
        "data.cache_exposure": "configure_security_headers",
        "data.error_disclosure": "sanitize_error_messages",
        "data.debug_enabled": "disable_debug_mode",
        # Deserialization categories
        "deserialization.unsafe_pickle": "use_safe_deserializer",
        "deserialization.unsafe_yaml": "use_safe_deserializer",
        "deserialization.unsafe_json": "use_safe_deserializer",
        "deserialization.unsafe_xml": "use_safe_parser",
        "deserialization.prototype_pollution": "use_safe_api",
        "deserialization.unsafe": "use_safe_deserializer",
        # Path & File categories
        "path.traversal": "canonicalize_path",
        "path.local_file_inclusion": "validate_path",
        "path.remote_file_inclusion": "validate_path",
        "file.arbitrary_write": "restrict_file_access",
        "file.arbitrary_read": "restrict_file_access",
        "file.unsafe_upload": "validate_file_type",
        "file.symlink_attack": "canonicalize_path",
        "file.race_condition": "refactor_logic",
        # Network categories
        "ssrf": "whitelist_input",
        "ssrf.internal_network": "whitelist_input",
        "ssrf.cloud_metadata": "whitelist_input",
        "open_redirect": "whitelist_input",
        "request.smuggling": "use_safe_api",
        "request.splitting": "sanitize_input",
        "dns.rebinding": "whitelist_input",
        # Unsafe exec categories
        "unsafe.exec": "remove_eval_exec",
        "unsafe.eval": "remove_eval_exec",
        "unsafe.code_injection": "remove_eval_exec",
        "unsafe.dynamic_import": "use_safe_api",
        "unsafe.reflection": "sanitize_input",
        "unsafe.jit_spray": "use_safe_api",
        # DoS categories
        "dos.regex": "sanitize_input",
        "dos.xml_bomb": "use_safe_parser",
        "dos.zip_bomb": "limit_file_size",
        "dos.resource_exhaustion": "add_resource_limits",
        "dos.uncontrolled_recursion": "add_resource_limits",
        "dos.infinite_loop": "implement_timeout",
        # Dependency categories
        "dependency.known_vuln": "upgrade_dependency",
        "dependency.outdated": "upgrade_dependency",
        "dependency.typosquat": "remove_vulnerable_dependency",
        "dependency.malicious": "remove_vulnerable_dependency",
        "dependency.license_violation": "use_alternative_package",
        "dependency.vuln": "upgrade_dependency",
        # Memory categories
        "memory.buffer_overflow": "use_safe_api",
        "memory.use_after_free": "refactor_logic",
        "memory.null_pointer": "add_error_handling",
        "memory.integer_overflow": "validate_input",
        "memory.format_string": "use_safe_api",
        "type.unsafe_cast": "use_safe_api",
        "type.prototype_pollution": "use_safe_api",
        # Config categories
        "config.insecure_default": "restrict_permissions",
        "config.exposed_admin": "add_auth_check",
        "config.debug_mode": "disable_debug_mode",
        "config.verbose_errors": "sanitize_error_messages",
        "config.insecure_permissions": "restrict_permissions",
        "config.missing_security_headers": "configure_security_headers",
        # Logging categories
        "logging.insufficient": "enable_logging",
        "logging.sensitive_data": "sanitize_output",
        "logging.injection": "sanitize_input",
        # Logic categories
        "logic.race_condition": "refactor_logic",
        "logic.time_of_check": "refactor_logic",
        "logic.insufficient_validation": "validate_input",
        "logic.bypass": "refactor_logic",
        # Misc categories
        "misc.information_disclosure": "sanitize_output",
        "misc.deprecated_api": "replace_deprecated_api",
        "misc.code_quality": "refactor_logic",
        "misc.other": "unknown",
    }

    return category_fix_map.get(category, "unknown")


def infer_verdict(
    rule_id: str,
    message: str,
    filepath: str,
    code_snippet: str | None,
    severity: str,
    confidence: str | None = None,
) -> tuple[str, str]:
    """
    Infer verdict (TP, FP, UNCERTAIN) based on comprehensive context analysis.
    Returns (verdict, reason) tuple.
    """
    combined = f"{rule_id} {message}".lower()
    code = (code_snippet or "").lower()
    filepath_lower = filepath.lower()

    # =========================================================================
    # PHASE 1: Check for definite FALSE POSITIVES based on path/context
    # =========================================================================

    # Check path-based FP patterns
    for pattern in FP_PATH_PATTERNS:
        if re.search(pattern, filepath_lower, re.IGNORECASE):
            return ("FP", f"File path matches FP pattern: {pattern[:30]}...")

    # Check rule-specific FP overrides
    for rule_pattern, fp_contexts in RULE_FP_OVERRIDES.items():
        if re.search(rule_pattern, rule_id, re.IGNORECASE):
            for context_pattern in fp_contexts:
                if re.search(context_pattern, filepath_lower + " " + code, re.IGNORECASE):
                    return ("FP", f"Rule {rule_id} in non-production context")

    # Check code-level FP patterns (nosec, test assertions, etc.)
    for pattern in FP_CODE_PATTERNS:
        if re.search(pattern, code, re.IGNORECASE):
            return ("FP", f"Code contains FP indicator: {pattern[:30]}...")

    # =========================================================================
    # PHASE 2: Check for definite TRUE POSITIVES based on dangerous patterns
    # =========================================================================

    for pattern, description in TP_PATTERNS:
        if re.search(pattern, code, re.IGNORECASE):
            return ("TP", f"High-risk pattern: {description}")

    # =========================================================================
    # PHASE 3: Rule-specific analysis
    # =========================================================================

    # B101: assert - almost always FP (used for debugging/testing)
    if "B101" in rule_id or "assert" in rule_id.lower():
        # Only TP if it's in a critical security path
        if any(kw in filepath_lower for kw in ["auth", "security", "permission", "access"]):
            return ("UNCERTAIN", "Assert in security-critical file - needs review")
        return ("FP", "Assert statement - debugging/testing construct, not security issue")

    # B110: try-except-pass - context dependent
    if "B110" in rule_id:
        if any(kw in code for kw in ["security", "auth", "password", "token", "secret"]):
            return ("TP", "Silent exception in security-sensitive code")
        return ("FP", "Try-except-pass in non-security context")

    # B404: subprocess import - just an import
    if "B404" in rule_id:
        return ("FP", "Importing subprocess is not a vulnerability")

    # B311: random - depends on usage
    if "B311" in rule_id or "random" in rule_id.lower():
        if any(kw in code for kw in ["secret", "token", "password", "key", "salt", "nonce", "iv"]):
            return ("TP", "Insecure random used for cryptographic purpose")
        if any(kw in code for kw in ["shuffle", "sample", "choice", "color", "display", "game"]):
            return ("FP", "Random used for non-cryptographic purpose")
        return ("UNCERTAIN", "Random usage needs context review")

    # B105/B106/B107: hardcoded passwords
    if re.search(r"B10[567]", rule_id):
        # Check if it looks like a real secret or a placeholder
        if any(kw in code for kw in ["xxx", "placeholder", "changeme", "example", "your_", "TODO"]):
            return ("FP", "Placeholder password, not a real secret")
        if any(kw in filepath_lower for kw in ["test", "example", "sample", "config"]):
            return ("FP", "Hardcoded password in test/example file")
        return ("TP", "Hardcoded password in production code")

    # innerHTML/XSS in vendor code
    if "innerhtml" in rule_id.lower() or "xss" in message.lower():
        if any(
            vendor in filepath_lower
            for vendor in ["ckeditor", "tinymce", "vendor", "node_modules", ".min.js"]
        ):
            return ("FP", "XSS finding in vendor/third-party code")
        if re.search(r"request|user|param|input", code):
            return ("TP", "XSS with potential user input")
        return ("UNCERTAIN", "XSS pattern needs context review")

    # =========================================================================
    # PHASE 4: Severity/Confidence based decision
    # =========================================================================

    sev_weight = SEVERITY_WEIGHTS.get(severity.upper(), 0.5)
    conf_weight = CONFIDENCE_WEIGHTS.get((confidence or "MEDIUM").upper(), 0.7)

    score = sev_weight * conf_weight

    if score >= 0.7:
        return ("TP", f"High severity ({severity}) and confidence")
    elif score <= 0.3:
        return ("UNCERTAIN", f"Low severity ({severity}) - needs manual review")

    # =========================================================================
    # PHASE 5: Default decision based on category
    # =========================================================================

    # Check for uncertain patterns in message
    for pattern in UNCERTAIN_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            return ("UNCERTAIN", "Message indicates uncertainty")

    # Default: assume TP for unmatched security findings
    return ("TP", f"Security finding from {rule_id}")


def infer_verdict_simple(
    rule_id: str,
    message: str,
    filepath: str,
    code_snippet: str | None,
    severity: str,
) -> str:
    """Backwards-compatible wrapper returning just the verdict."""
    verdict, _ = infer_verdict(rule_id, message, filepath, code_snippet, severity)
    return verdict


def generate_notes(
    verdict: str,
    category: str,
    fix_type: str,
    rule_id: str,
    message: str,
    filepath: str,
    code_snippet: str | None,
    severity: str,
    verdict_reason: str | None = None,
) -> str:
    """Generate detailed notes explaining the label decision."""
    notes_parts = []

    # Add verdict reason if provided
    if verdict_reason:
        notes_parts.append(f"[{verdict}] {verdict_reason}")

    # Explain verdict reasoning
    elif verdict == "FP":
        if re.search(r"test[-_]?|_test\.|\.test\.|spec\.", filepath, re.IGNORECASE):
            notes_parts.append(
                f"False positive: Finding in test file '{Path(filepath).name}' - test assertions are expected behavior, not production vulnerabilities."
            )
        elif re.search(r"example|demo|sample", filepath, re.IGNORECASE):
            notes_parts.append("False positive: Code is in example/demo file, not production code.")
        elif re.search(r"mock|fixture", filepath, re.IGNORECASE):
            notes_parts.append(
                "False positive: Code is in test mock/fixture, intentionally insecure for testing."
            )
        else:
            notes_parts.append(
                "False positive: Context indicates this is not a real vulnerability."
            )

    elif verdict == "UNCERTAIN":
        if severity.upper() in ("INFO", "INFORMATION"):
            notes_parts.append(
                f"Uncertain: Low severity ({severity}) finding requires manual review to confirm exploitability."
            )
        else:
            notes_parts.append(
                "Uncertain: Finding may be valid but requires additional context to confirm."
            )

    elif verdict == "TP":
        # Comprehensive category-specific explanations
        category_explanations = {
            # Injection categories
            "injection.sql": f"SQL Injection detected by '{rule_id}': Query construction uses string concatenation with user input. Attackers can manipulate queries to access/modify data or bypass authentication.",
            "injection.nosql": f"NoSQL Injection detected by '{rule_id}': NoSQL query operators in user input can bypass authentication or extract data. Use parameterized queries or input validation.",
            "injection.command": f"Command Injection detected by '{rule_id}': User input reaches shell execution. Attackers can execute arbitrary system commands.",
            "injection.xss": f"Cross-Site Scripting (XSS) detected by '{rule_id}': User input rendered without escaping. Attackers can inject malicious scripts to steal cookies or perform actions as users.",
            "injection.xxe": f"XML External Entity (XXE) detected by '{rule_id}': XML parser processes external entities. Attackers can read local files, perform SSRF, or cause DoS.",
            "injection.ldap": f"LDAP Injection detected by '{rule_id}': User input in LDAP queries. Attackers can modify queries to bypass authentication or access unauthorized data.",
            "injection.xpath": f"XPath Injection detected by '{rule_id}': User input in XPath queries. Attackers can extract data or bypass authentication.",
            "injection.template": f"Template Injection detected by '{rule_id}': User input in template expressions. Attackers can execute arbitrary code in the template engine.",
            "injection.header": f"Header Injection detected by '{rule_id}': User input in HTTP headers. Attackers can perform response splitting, cache poisoning, or XSS.",
            "injection.log": f"Log Injection detected by '{rule_id}': User input in log entries. Attackers can forge log entries or inject malicious content.",
            # Crypto categories
            "crypto.weak_algorithm": f"Weak Cryptographic Algorithm detected by '{rule_id}': Algorithm (MD5/SHA1/DES/RC4) is cryptographically broken. Use SHA-256+ or AES-GCM.",
            "crypto.weak_key": f"Weak Cryptographic Key detected by '{rule_id}': Key size is insufficient for security. Use at least 2048-bit RSA or 256-bit symmetric keys.",
            "crypto.weak_random": f"Weak Random Number Generator detected by '{rule_id}': Non-cryptographic PRNG used for security purposes. Use secrets module or os.urandom().",
            "crypto.insecure_mode": f"Insecure Crypto Mode detected by '{rule_id}': ECB mode or other insecure configuration. Use authenticated encryption (GCM/CCM).",
            "crypto.hardcoded_key": f"Hardcoded Cryptographic Key detected by '{rule_id}': Key embedded in source code. Store keys in environment variables or secret manager.",
            "crypto.insecure_tls": f"Insecure TLS Configuration detected by '{rule_id}': Outdated TLS version or weak cipher suites. Use TLS 1.2+ with strong ciphers.",
            "crypto.certificate_validation": f"Certificate Validation Disabled detected by '{rule_id}': SSL/TLS certificate verification disabled. This enables man-in-the-middle attacks.",
            "crypto.insecure": f"Insecure Cryptography detected by '{rule_id}': Weak cryptographic practice. Review and apply modern cryptographic standards.",
            # Auth categories
            "auth.broken_authentication": f"Broken Authentication detected by '{rule_id}': Authentication mechanism can be bypassed or is incorrectly implemented.",
            "auth.missing_authentication": f"Missing Authentication detected by '{rule_id}': Endpoint or resource lacks authentication. Add proper authentication checks.",
            "auth.session_fixation": f"Session Fixation detected by '{rule_id}': Session ID not regenerated after authentication. Regenerate session on login.",
            "auth.session_expiration": f"Session Expiration Issue detected by '{rule_id}': Sessions don't expire properly. Implement proper session timeout.",
            "auth.insecure_cookie": f"Insecure Cookie detected by '{rule_id}': Cookie missing Secure/HttpOnly/SameSite flags. Add appropriate cookie security attributes.",
            "auth.csrf": f"Cross-Site Request Forgery (CSRF) detected by '{rule_id}': Missing CSRF protection. Implement CSRF tokens or SameSite cookies.",
            "auth.cors_misconfiguration": f"CORS Misconfiguration detected by '{rule_id}': Overly permissive CORS policy. Restrict allowed origins.",
            "auth.jwt_vulnerability": f"JWT Vulnerability detected by '{rule_id}': JWT algorithm confusion, missing validation, or none algorithm accepted.",
            "auth.idor": f"Insecure Direct Object Reference (IDOR) detected by '{rule_id}': User can access resources of other users. Add authorization checks.",
            "auth.privilege_escalation": f"Privilege Escalation detected by '{rule_id}': User can gain elevated privileges. Implement proper role-based access control.",
            "auth.session": f"Session Security Issue detected by '{rule_id}': Session handling vulnerability. Review session management implementation.",
            # Secrets categories
            "secrets.hardcoded_password": f"Hardcoded Password detected by '{rule_id}': Password embedded in source code. Use environment variables or secret manager.",
            "secrets.hardcoded_api_key": f"Hardcoded API Key detected by '{rule_id}': API key in source code. Rotate immediately and use secret manager.",
            "secrets.hardcoded_token": f"Hardcoded Token detected by '{rule_id}': Access token in source code. Rotate and use secure token storage.",
            "secrets.hardcoded_private_key": f"Hardcoded Private Key detected by '{rule_id}': Private key embedded in code. Rotate key and use secure key management.",
            "secrets.exposed_in_log": f"Secret Exposed in Logs detected by '{rule_id}': Sensitive data written to logs. Sanitize log output.",
            "secrets.exposure": f"Secret Exposure detected by '{rule_id}': Credential or secret accessible. Rotate and implement secure storage.",
            # Data categories
            "data.pii_exposure": f"PII Exposure detected by '{rule_id}': Personal identifiable information not properly protected. Encrypt and limit access.",
            "data.debug_enabled": f"Debug Mode Enabled detected by '{rule_id}': Debug mode exposes sensitive information. Disable in production.",
            "data.error_disclosure": f"Error Information Disclosure detected by '{rule_id}': Detailed errors expose internal information. Use generic error messages.",
            # Deserialization categories
            "deserialization.unsafe_pickle": f"Unsafe Pickle Deserialization detected by '{rule_id}': Pickle can execute arbitrary code. Use json or other safe formats.",
            "deserialization.unsafe_yaml": f"Unsafe YAML Loading detected by '{rule_id}': yaml.load() executes code. Use yaml.safe_load() instead.",
            "deserialization.prototype_pollution": f"Prototype Pollution detected by '{rule_id}': Object prototype can be modified via user input. Validate and freeze prototypes.",
            "deserialization.unsafe": f"Unsafe Deserialization detected by '{rule_id}': Deserializing untrusted data can lead to code execution.",
            # Path categories
            "path.traversal": f"Path Traversal detected by '{rule_id}': User input in file path allows ../ sequences. Canonicalize and validate paths.",
            "path.local_file_inclusion": f"Local File Inclusion detected by '{rule_id}': User can include arbitrary local files. Validate against whitelist.",
            "file.arbitrary_write": f"Arbitrary File Write detected by '{rule_id}': User can write to arbitrary paths. Restrict write locations.",
            "file.unsafe_upload": f"Unsafe File Upload detected by '{rule_id}': File upload lacks proper validation. Validate type, size, and store securely.",
            # Network categories
            "ssrf": f"Server-Side Request Forgery (SSRF) detected by '{rule_id}': User-controlled URLs can access internal resources. Validate against allowlist.",
            "ssrf.cloud_metadata": f"Cloud Metadata SSRF detected by '{rule_id}': Can access cloud instance metadata (169.254.169.254). Block internal IPs.",
            "open_redirect": f"Open Redirect detected by '{rule_id}': User can control redirect destination. Validate against allowlist.",
            # Unsafe code categories
            "unsafe.exec": f"Unsafe exec() detected by '{rule_id}': exec() executes arbitrary code. Remove or use safe alternatives.",
            "unsafe.eval": f"Unsafe eval() detected by '{rule_id}': eval() executes arbitrary code. Remove or use ast.literal_eval() for data.",
            "unsafe.code_injection": f"Code Injection detected by '{rule_id}': User input leads to code execution. Sanitize or remove dynamic code.",
            # DoS categories
            "dos.regex": f"Regular Expression DoS (ReDoS) detected by '{rule_id}': Regex can cause catastrophic backtracking. Simplify or add timeout.",
            "dos.xml_bomb": f"XML Bomb detected by '{rule_id}': XML entity expansion can cause memory exhaustion. Disable entity expansion.",
            "dos.resource_exhaustion": f"Resource Exhaustion detected by '{rule_id}': Unbounded resource usage can cause DoS. Add limits and timeouts.",
            # Dependency categories
            "dependency.known_vuln": f"Known Vulnerability in Dependency detected by '{rule_id}': Upgrade to patched version immediately.",
            "dependency.outdated": f"Outdated Dependency detected by '{rule_id}': May contain unfixed vulnerabilities. Update to latest stable version.",
            # Config categories
            "config.debug_mode": f"Debug Mode Enabled detected by '{rule_id}': Exposes sensitive info and may enable code execution. Disable in production.",
            "config.missing_security_headers": f"Missing Security Headers detected by '{rule_id}': Add X-Frame-Options, CSP, X-Content-Type-Options headers.",
            # Logic categories
            "logic.race_condition": f"Race Condition detected by '{rule_id}': Time-of-check to time-of-use vulnerability. Use atomic operations or locks.",
        }

        if category in category_explanations:
            notes_parts.append(category_explanations[category])
        else:
            notes_parts.append(
                f"True positive: Security issue detected by rule '{rule_id}'. Category: {category}. Severity: {severity}."
            )

    # Add code context if available
    if code_snippet and len(code_snippet) < 200:
        snippet_preview = code_snippet.strip().replace("\n", " ")[:100]
        notes_parts.append(f"Code context: `{snippet_preview}...`")

    # Comprehensive fix type explanations
    fix_explanations = {
        # Input handling
        "sanitize_input": "Validate, sanitize, and encode all user inputs before use.",
        "validate_input": "Implement strict input validation using allowlists where possible.",
        "whitelist_input": "Only allow explicitly permitted values; reject everything else.",
        "limit_input_length": "Enforce maximum length limits on all user inputs.",
        # Output handling
        "escape_output": "Apply context-appropriate escaping (HTML, JS, URL, SQL, etc.).",
        "sanitize_output": "Remove or redact sensitive data from output.",
        # Query & Command
        "parameterize_query": "Use parameterized queries or prepared statements; never concatenate user input into queries.",
        "use_orm": "Use an ORM which handles parameterization automatically.",
        "use_subprocess_list": "Use subprocess with a list of arguments and shell=False.",
        "avoid_shell_execution": "Avoid shell execution entirely; use direct process execution.",
        # API & Library
        "use_safe_api": "Replace with a secure API or library function.",
        "use_safe_parser": "Use a parser with security features enabled (e.g., defusedxml).",
        "use_safe_deserializer": "Use safe deserialization (json.loads, yaml.safe_load).",
        # Code changes
        "remove_eval_exec": "Remove eval/exec; use ast.literal_eval for data, or refactor logic.",
        "remove_dangerous_code": "Remove or refactor the dangerous code pattern.",
        "replace_deprecated_api": "Replace deprecated API with current secure alternative.",
        "refactor_logic": "Refactor the code logic to eliminate the vulnerability.",
        # Path & File
        "validate_path": "Validate file paths against allowed directories.",
        "canonicalize_path": "Use os.path.realpath() and validate the canonical path.",
        "restrict_file_access": "Limit file operations to specific directories only.",
        "validate_file_type": "Validate file type using magic bytes, not just extension.",
        "limit_file_size": "Enforce maximum file size limits.",
        # Secrets
        "rotate_secret": "Rotate the compromised secret immediately.",
        "use_secret_manager": "Store secrets in a dedicated secret manager (HashiCorp Vault, AWS Secrets Manager).",
        "use_environment_variable": "Load secrets from environment variables, not source code.",
        "remove_hardcoded_secret": "Remove hardcoded secret and use secure storage.",
        # Crypto
        "upgrade_algorithm": "Use modern algorithms: SHA-256+, AES-256-GCM, RSA-2048+.",
        "use_strong_key": "Use cryptographically strong keys of adequate length.",
        "use_secure_random": "Use secrets module or os.urandom() for cryptographic randomness.",
        "enable_certificate_validation": "Enable SSL/TLS certificate validation; do not disable verify.",
        "use_tls_1_3": "Use TLS 1.2 or 1.3 with strong cipher suites.",
        "add_integrity_check": "Add message authentication (HMAC or authenticated encryption).",
        # Auth
        "add_auth_check": "Implement proper authentication checks before sensitive operations.",
        "add_authorization_check": "Verify user is authorized to access the specific resource.",
        "add_csrf_protection": "Implement CSRF tokens or use SameSite cookies.",
        "configure_cors_properly": "Restrict CORS to specific trusted origins.",
        "secure_session_config": "Configure secure session settings (timeout, regeneration, flags).",
        "use_secure_cookie_flags": "Set Secure, HttpOnly, and SameSite flags on cookies.",
        # Dependency
        "upgrade_dependency": "Update to the latest patched version of the dependency.",
        "remove_vulnerable_dependency": "Remove the vulnerable or malicious dependency entirely.",
        "use_alternative_package": "Replace with a secure alternative package.",
        # Config
        "disable_debug_mode": "Disable debug mode in production configuration.",
        "configure_security_headers": "Add security headers: CSP, X-Frame-Options, X-Content-Type-Options.",
        "restrict_permissions": "Apply principle of least privilege to permissions.",
        # Error handling
        "add_error_handling": "Add proper error handling with safe fallbacks.",
        "sanitize_error_messages": "Use generic error messages; log details server-side only.",
        # Resource limits
        "add_resource_limits": "Implement resource limits (memory, CPU, time).",
        "implement_timeout": "Add timeouts to prevent hanging operations.",
        "add_rate_limiting": "Implement rate limiting to prevent abuse.",
        # Testing
        "add_tests": "Add test coverage for the security fix.",
        "add_security_tests": "Add security-specific test cases.",
        # No action
        "no_fix_needed": "No fix required; finding is informational or acceptable risk.",
        "accept_risk": "Risk accepted with documented justification.",
        "unknown": "Fix type requires manual analysis.",
    }

    if fix_type in fix_explanations and verdict == "TP":
        notes_parts.append(f"Remediation: {fix_explanations[fix_type]}")

    return " | ".join(notes_parts) if notes_parts else f"Auto-labeled based on rule: {rule_id}"


def auto_label_item(item: dict[str, Any]) -> dict[str, Any]:
    """Generate automatic labels for an item with enhanced analysis."""
    finding = item.get("finding") or {}
    rule_id = finding.get("rule_id") or ""
    message = finding.get("message") or ""
    severity = finding.get("severity") or "MEDIUM"
    confidence = finding.get("confidence")
    filepath = item.get("filepath") or ""
    code_snippet = item.get("code_snippet")

    category = infer_category(rule_id, message)
    fix_type = infer_fix_type(rule_id, message, category)

    # Use enhanced verdict function with reason
    verdict, verdict_reason = infer_verdict(
        rule_id, message, filepath, code_snippet, severity, confidence
    )

    notes = generate_notes(
        verdict=verdict,
        category=category,
        fix_type=fix_type,
        rule_id=rule_id,
        message=message,
        filepath=filepath,
        code_snippet=code_snippet,
        severity=severity,
        verdict_reason=verdict_reason,
    )

    return {
        "verdict": verdict,
        "category": category,
        "fix_type": fix_type,
        "notes": notes,
        "verdict_reason": verdict_reason,
    }


def _parse_severity_weights(raw: str) -> dict[str, int]:
    weights = {}
    for part in raw.split(","):
        if not part.strip():
            continue
        key, value = part.split("=")
        weights[key.strip().upper()] = int(value.strip())
    return weights


@app.command()
def label(
    inputs: str = typer.Option("datasets/python/all.jsonl,datasets/ts/all.jsonl"),
    selected: Path = typer.Option(Path("datasets/gold/selected_items.jsonl")),
    out: Path = typer.Option(Path("datasets/gold/gold_labels.jsonl")),
    annotator: str = typer.Option("auto"),
    resume: bool = typer.Option(True),
    max_items: int | None = typer.Option(None),
    target_n: int = typer.Option(300),
    seed: int = typer.Option(1337),
    overlap_ratio: float = typer.Option(0.1),
    per_rule_cap: int = typer.Option(25),
    severity_weights: str = typer.Option("HIGH=3,MEDIUM=2,LOW=1,INFO=1"),
    dry_run: bool = typer.Option(False, help="Preview labels without saving"),
) -> None:
    """Automatically label items using heuristics."""
    input_paths = parse_inputs(inputs)

    if not selected.exists():
        generate_selection(
            inputs=input_paths,
            selected_path=selected,
            target_n=target_n,
            seed=seed,
            overlap_ratio=overlap_ratio,
            per_rule_cap=per_rule_cap,
            severity_weights=_parse_severity_weights(severity_weights),
        )

    items = load_selected_items(selected)
    labeled_keys = load_labeled_keys(out, annotator) if resume else set()
    out.parent.mkdir(parents=True, exist_ok=True)

    labeled = 0
    stats = {"TP": 0, "FP": 0, "UNCERTAIN": 0}

    with out.open("a", encoding="utf-8") as handle:
        for item in items:
            if max_items is not None and labeled >= max_items:
                break

            sample_id = item.get("sample_id")
            if not isinstance(sample_id, str):
                continue

            finding_obj = item.get("finding")
            finding: dict[str, Any] = finding_obj if isinstance(finding_obj, dict) else {}
            if not finding:
                continue

            key = _label_key(sample_id, finding, annotator)
            if resume and key in labeled_keys:
                continue

            language = item.get("language")
            if language not in {"python", "ts"}:
                continue

            repo = item.get("repo")
            if not isinstance(repo, str):
                continue

            commit = item.get("commit")
            if not isinstance(commit, str):
                continue

            filepath = item.get("filepath")
            if not isinstance(filepath, str):
                continue

            span_obj = item.get("span")
            if not isinstance(span_obj, dict):
                continue

            # Auto-generate labels
            response = auto_label_item(item)
            stats[response["verdict"]] += 1

            if dry_run:
                typer.echo(f"[DRY-RUN] {filepath}: {response['verdict']} - {response['category']}")
                labeled += 1
                continue

            span_ref = SpanRef.model_validate(span_obj)
            finding_ref = FindingRef.model_validate(finding)

            gold_label = GoldLabel(
                sample_id=sample_id,
                language=language,
                repo=repo,
                commit=commit,
                filepath=filepath,
                span=span_ref,
                finding=finding_ref,
                verdict=response["verdict"],
                category=response["category"],
                fix_type=response["fix_type"],
                annotator_id=annotator,
                labeled_at=datetime.utcnow().isoformat(),
                notes=response.get("notes"),
                duplicate_group=item.get("duplicate_group"),
                schema_version="1.0",
            )

            handle.write(json.dumps(gold_label.model_dump(), ensure_ascii=True) + "\n")
            handle.flush()
            labeled_keys.add(key)
            labeled += 1

    typer.echo(f"\nLabeled {labeled} items")
    typer.echo(f"Stats: TP={stats['TP']}, FP={stats['FP']}, UNCERTAIN={stats['UNCERTAIN']}")
    if not dry_run:
        typer.echo(f"Saved to: {out}")


@app.command()
def preview(
    selected: Path = typer.Option(Path("datasets/gold/selected_items.jsonl")),
    max_items: int = typer.Option(10),
) -> None:
    """Preview what auto-labeling would produce."""
    if not selected.exists():
        typer.echo(f"Selected items not found: {selected}")
        raise typer.Exit(code=1)

    items = load_selected_items(selected)

    for i, item in enumerate(items[:max_items]):
        finding = item.get("finding") or {}
        filepath = item.get("filepath") or "unknown"
        rule_id = finding.get("rule_id") or "unknown"

        response = auto_label_item(item)

        typer.echo(f"\n--- Item {i+1} ---")
        typer.echo(f"File: {filepath}")
        typer.echo(f"Rule: {rule_id}")
        typer.echo(f"Verdict: {response['verdict']}")
        typer.echo(f"Category: {response['category']}")
        typer.echo(f"Fix Type: {response['fix_type']}")
        typer.echo(f"Notes: {response['notes']}")


if __name__ == "__main__":
    app()
