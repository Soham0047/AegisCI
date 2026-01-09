"""Configuration management for SecureDev Guardian CLI."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from guardian.version import DEFAULT_CONFIG


class Config:
    """Configuration manager with file and environment support."""

    CONFIG_FILENAMES = [
        ".guardian.yaml",
        ".guardian.yml",
        "guardian.yaml",
        "guardian.yml",
    ]

    def __init__(self) -> None:
        self._config: dict[str, Any] = dict(DEFAULT_CONFIG)
        self._config_path: Path | None = None

    def load(self, config_path: Path | None = None) -> "Config":
        """Load configuration from file and environment."""
        # 1. Load from config file
        if config_path:
            self._load_file(config_path)
        else:
            self._auto_discover()

        # 2. Override with environment variables
        self._load_env()

        return self

    def _auto_discover(self) -> None:
        """Auto-discover config file in current directory or home."""
        search_dirs = [Path.cwd(), Path.home()]

        for search_dir in search_dirs:
            for filename in self.CONFIG_FILENAMES:
                config_path = search_dir / filename
                if config_path.exists():
                    self._load_file(config_path)
                    return

    def _load_file(self, path: Path) -> None:
        """Load configuration from YAML file."""
        if not path.exists():
            return

        try:
            content = path.read_text(encoding="utf-8")
            data = yaml.safe_load(content) or {}
            if isinstance(data, dict):
                self._config.update(data)
                self._config_path = path
        except Exception:
            pass  # Silently ignore invalid config files

    def _load_env(self) -> None:
        """Load configuration from environment variables."""
        env_mappings = {
            "GUARDIAN_BASE_REF": "base_ref",
            "GUARDIAN_SEMGREP_CONFIG": "semgrep_config",
            "GUARDIAN_OUTPUT_DIR": "output_dir",
            "GUARDIAN_ARTIFACTS_DIR": "artifacts_dir",
            "GUARDIAN_FAIL_ON": "fail_on_severity",
            "GUARDIAN_VERBOSE": "verbose",
            "GUARDIAN_QUIET": "quiet",
            "GUARDIAN_NO_COLOR": "color",
        }

        for env_var, config_key in env_mappings.items():
            value = os.environ.get(env_var)
            if value is not None:
                if config_key in ("verbose", "quiet"):
                    self._config[config_key] = value.lower() in ("1", "true", "yes")
                elif config_key == "color":
                    self._config[config_key] = value.lower() not in ("1", "true", "yes")
                else:
                    self._config[config_key] = value

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        return self._config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set a configuration value."""
        self._config[key] = value

    @property
    def config_path(self) -> Path | None:
        """Return the path to the loaded config file."""
        return self._config_path

    def to_dict(self) -> dict[str, Any]:
        """Return configuration as dictionary."""
        return dict(self._config)


# Global config instance
config = Config()
