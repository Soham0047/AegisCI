from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Comprehensive security vulnerability categories
CATEGORY_VOCAB = (
    # Injection vulnerabilities
    "injection.sql",
    "injection.nosql",
    "injection.command",
    "injection.xss",
    "injection.xxe",
    "injection.ldap",
    "injection.xpath",
    "injection.template",
    "injection.header",
    "injection.log",
    "injection.email",
    "injection.regex",
    # Cryptography issues
    "crypto.weak_algorithm",
    "crypto.weak_key",
    "crypto.weak_random",
    "crypto.insecure_mode",
    "crypto.missing_integrity",
    "crypto.hardcoded_key",
    "crypto.insecure_tls",
    "crypto.certificate_validation",
    "crypto.insecure",  # Generic fallback
    # Authentication & Authorization
    "auth.broken_authentication",
    "auth.missing_authentication",
    "auth.weak_password",
    "auth.session_fixation",
    "auth.session_expiration",
    "auth.insecure_cookie",
    "auth.csrf",
    "auth.cors_misconfiguration",
    "auth.jwt_vulnerability",
    "auth.oauth_misconfiguration",
    "auth.privilege_escalation",
    "auth.idor",
    "auth.session",  # Generic fallback
    # Secrets & Credentials
    "secrets.hardcoded_password",
    "secrets.hardcoded_api_key",
    "secrets.hardcoded_token",
    "secrets.hardcoded_private_key",
    "secrets.exposed_in_log",
    "secrets.exposed_in_error",
    "secrets.insecure_storage",
    "secrets.exposure",  # Generic fallback
    # Data exposure
    "data.sensitive_exposure",
    "data.pii_exposure",
    "data.insufficient_encryption",
    "data.insecure_transmission",
    "data.cache_exposure",
    "data.error_disclosure",
    "data.debug_enabled",
    # Deserialization
    "deserialization.unsafe_pickle",
    "deserialization.unsafe_yaml",
    "deserialization.unsafe_json",
    "deserialization.unsafe_xml",
    "deserialization.prototype_pollution",
    "deserialization.unsafe",  # Generic fallback
    # File & Path issues
    "path.traversal",
    "path.local_file_inclusion",
    "path.remote_file_inclusion",
    "file.arbitrary_write",
    "file.arbitrary_read",
    "file.unsafe_upload",
    "file.symlink_attack",
    "file.race_condition",
    # Network & Request issues
    "ssrf",
    "ssrf.internal_network",
    "ssrf.cloud_metadata",
    "open_redirect",
    "request.smuggling",
    "request.splitting",
    "dns.rebinding",
    # Code execution
    "unsafe.exec",
    "unsafe.eval",
    "unsafe.code_injection",
    "unsafe.dynamic_import",
    "unsafe.reflection",
    "unsafe.jit_spray",
    # Resource & DoS
    "dos.regex",
    "dos.xml_bomb",
    "dos.zip_bomb",
    "dos.resource_exhaustion",
    "dos.uncontrolled_recursion",
    "dos.infinite_loop",
    # Dependency & Supply chain
    "dependency.known_vuln",
    "dependency.outdated",
    "dependency.typosquat",
    "dependency.malicious",
    "dependency.license_violation",
    "dependency.vuln",  # Generic fallback
    # Memory & Type safety
    "memory.buffer_overflow",
    "memory.use_after_free",
    "memory.null_pointer",
    "memory.integer_overflow",
    "memory.format_string",
    "type.unsafe_cast",
    "type.prototype_pollution",
    # Configuration & Deployment
    "config.insecure_default",
    "config.exposed_admin",
    "config.debug_mode",
    "config.verbose_errors",
    "config.insecure_permissions",
    "config.missing_security_headers",
    # Logging & Monitoring
    "logging.insufficient",
    "logging.sensitive_data",
    "logging.injection",
    # Business logic
    "logic.race_condition",
    "logic.time_of_check",
    "logic.insufficient_validation",
    "logic.bypass",
    # Miscellaneous
    "misc.information_disclosure",
    "misc.deprecated_api",
    "misc.code_quality",
    "misc.other",
)

# Comprehensive fix type vocabulary
FIX_TYPE_VOCAB = (
    # Input handling
    "sanitize_input",
    "validate_input",
    "encode_input",
    "whitelist_input",
    "limit_input_length",
    # Output handling
    "escape_output",
    "encode_output",
    "sanitize_output",
    "use_content_security_policy",
    # Query & Command safety
    "parameterize_query",
    "use_orm",
    "use_prepared_statement",
    "avoid_shell_execution",
    "use_subprocess_list",
    # API & Library changes
    "use_safe_api",
    "use_safe_library",
    "use_safe_parser",
    "use_safe_serializer",
    "use_safe_deserializer",
    # Code removal/replacement
    "remove_eval_exec",
    "remove_dangerous_code",
    "replace_deprecated_api",
    "refactor_logic",
    # Path & File handling
    "validate_path",
    "canonicalize_path",
    "restrict_file_access",
    "validate_file_type",
    "limit_file_size",
    # Secrets management
    "rotate_secret",
    "use_secret_manager",
    "use_environment_variable",
    "remove_hardcoded_secret",
    "encrypt_at_rest",
    # Cryptography fixes
    "upgrade_algorithm",
    "use_strong_key",
    "use_secure_random",
    "enable_certificate_validation",
    "use_tls_1_3",
    "add_integrity_check",
    # Authentication & Authorization
    "add_auth_check",
    "add_authorization_check",
    "implement_rate_limiting",
    "add_csrf_protection",
    "configure_cors_properly",
    "secure_session_config",
    "use_secure_cookie_flags",
    "implement_mfa",
    # Dependency management
    "upgrade_dependency",
    "pin_dependency_version",
    "remove_vulnerable_dependency",
    "use_alternative_package",
    # Configuration
    "disable_debug_mode",
    "configure_security_headers",
    "restrict_permissions",
    "enable_logging",
    "configure_timeout",
    # Error handling
    "add_error_handling",
    "sanitize_error_messages",
    "implement_graceful_degradation",
    # Testing & Validation
    "add_tests",
    "add_security_tests",
    "add_input_validation_tests",
    # Resource limits
    "add_resource_limits",
    "implement_timeout",
    "add_rate_limiting",
    # No action needed
    "no_fix_needed",
    "accept_risk",
    "wontfix",
    "unknown",
)

SCHEMA_VERSION = "1.0"


class FindingRef(BaseModel):
    source: str
    rule_id: str
    severity: str
    confidence: str | None
    message: str
    line: int | None


class SpanRef(BaseModel):
    start_line: int
    end_line: int
    start_col: int
    end_col: int


class GoldLabel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sample_id: str
    language: Literal["python", "ts"]
    repo: str
    commit: str
    filepath: str
    span: SpanRef
    finding: FindingRef
    verdict: Literal["TP", "FP", "UNCERTAIN"]
    category: str
    fix_type: str
    annotator_id: str
    labeled_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    notes: str | None
    duplicate_group: str | None
    schema_version: str = SCHEMA_VERSION

    @field_validator("category")
    @classmethod
    def _validate_category(cls, value: str) -> str:
        if value not in CATEGORY_VOCAB:
            raise ValueError(f"Invalid category: {value}")
        return value

    @field_validator("fix_type")
    @classmethod
    def _validate_fix_type(cls, value: str) -> str:
        if value not in FIX_TYPE_VOCAB:
            raise ValueError(f"Invalid fix_type: {value}")
        return value
