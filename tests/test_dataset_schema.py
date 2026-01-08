import pytest
from pydantic import ValidationError

from guardian.data.schema import Sample


def test_sample_schema_validates() -> None:
    sample = {
        "sample_id": "abc123",
        "language": "python",
        "repo": "local/repo",
        "commit": "WORKDIR",
        "filepath": "src/app.py",
        "code_snippet": "def hello():\n    return 1",
        "function_span": {
            "start_line": 1,
            "end_line": 2,
            "start_col": 0,
            "end_col": 0,
        },
        "context_before": "",
        "context_after": "",
        "weak_labels": [
            {
                "source": "bandit",
                "rule_id": "B101",
                "severity": "HIGH",
                "confidence": "MEDIUM",
                "message": "Example",
                "line": 1,
                "extra": {},
            }
        ],
        "gold_labels": None,
        "metadata": {
            "file_ext": ".py",
            "n_lines": 2,
            "cyclomatic_complexity": 1,
            "dependencies": {"python": [], "npm": []},
            "tool_versions": {},
        },
    }
    Sample.model_validate(sample)


def test_sample_schema_missing_field_fails() -> None:
    sample = {
        "language": "python",
        "repo": "local/repo",
        "commit": "WORKDIR",
        "filepath": "src/app.py",
        "code_snippet": "def hello():\n    return 1",
        "function_span": {
            "start_line": 1,
            "end_line": 2,
            "start_col": 0,
            "end_col": 0,
        },
        "context_before": "",
        "context_after": "",
        "weak_labels": [],
        "gold_labels": None,
        "metadata": {
            "file_ext": ".py",
            "n_lines": 2,
            "cyclomatic_complexity": 1,
            "dependencies": {"python": [], "npm": []},
            "tool_versions": {},
        },
    }
    with pytest.raises(ValidationError):
        Sample.model_validate(sample)
