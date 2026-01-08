import pytest
from pydantic import ValidationError

from guardian.data.gold_schema import GoldLabel


def test_gold_label_validates() -> None:
    label = GoldLabel(
        sample_id="sample1",
        language="python",
        repo="local/repo",
        commit="WORKDIR",
        filepath="app.py",
        span={"start_line": 1, "end_line": 2, "start_col": 0, "end_col": 0},
        finding={
            "source": "bandit",
            "rule_id": "B101",
            "severity": "HIGH",
            "confidence": "MEDIUM",
            "message": "Use of assert detected.",
            "line": 1,
        },
        verdict="TP",
        category="unsafe.exec",
        fix_type="no_fix_needed",
        annotator_id="alice",
        notes=None,
        duplicate_group=None,
    )
    assert label.schema_version == "1.0"


def test_gold_label_invalid_category() -> None:
    with pytest.raises(ValidationError):
        GoldLabel(
            sample_id="sample1",
            language="python",
            repo="local/repo",
            commit="WORKDIR",
            filepath="app.py",
            span={"start_line": 1, "end_line": 2, "start_col": 0, "end_col": 0},
            finding={
                "source": "bandit",
                "rule_id": "B101",
                "severity": "HIGH",
                "confidence": "MEDIUM",
                "message": "Use of assert detected.",
                "line": 1,
            },
            verdict="TP",
            category="invalid.category",
            fix_type="no_fix_needed",
            annotator_id="alice",
            notes=None,
            duplicate_group=None,
        )


def test_gold_label_invalid_fix_type() -> None:
    with pytest.raises(ValidationError):
        GoldLabel(
            sample_id="sample1",
            language="python",
            repo="local/repo",
            commit="WORKDIR",
            filepath="app.py",
            span={"start_line": 1, "end_line": 2, "start_col": 0, "end_col": 0},
            finding={
                "source": "bandit",
                "rule_id": "B101",
                "severity": "HIGH",
                "confidence": "MEDIUM",
                "message": "Use of assert detected.",
                "line": 1,
            },
            verdict="TP",
            category="unsafe.exec",
            fix_type="invalid.fix",
            annotator_id="alice",
            notes=None,
            duplicate_group=None,
        )
