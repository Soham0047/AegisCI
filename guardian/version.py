"""SecureDev Guardian version and constants."""

__version__ = "1.0.0"
__app_name__ = "SecureDev Guardian"
__description__ = "AI-powered security scanner with automated patching"

# Exit codes
EXIT_SUCCESS = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_CONFIG_ERROR = 3

# Default configuration
DEFAULT_CONFIG = {
    "base_ref": "main",
    "semgrep_config": "max",
    "output_dir": ".",
    "artifacts_dir": "artifacts",
    "report_format": "both",  # md, json, both
    "fail_on_severity": None,  # critical, high, medium, low, or None
    "verbose": False,
    "quiet": False,
    "color": True,
}

# Severity levels with their exit behavior
SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]
SEVERITY_COLORS = {
    "critical": "red bold",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}
