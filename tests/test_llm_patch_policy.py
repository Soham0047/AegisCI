from pathlib import Path

from patcher.policy import evaluate_llm_diff
from patcher.types import NormalizedFinding


def _make_finding(filepath: str, start: int, end: int, category: str) -> NormalizedFinding:
    return NormalizedFinding(
        finding_id=f"{filepath}:{start}",
        rule_id="demo.rule",
        category=category,
        filepath=filepath,
        start_line=start,
        end_line=end,
        start_col=None,
        end_col=None,
        source="semgrep",
        raw={},
        extra={},
    )


def test_policy_allows_localized_change(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    path = repo / "app.js"
    lines = [f"line {i}" for i in range(1, 21)]
    lines[9] = "el.innerHTML = user"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    diff = (
        "--- a/app.js\n"
        "+++ b/app.js\n"
        "@@ -10,1 +10,1 @@\n"
        "-el.innerHTML = user\n"
        "+el.textContent = user\n"
    )
    decision = evaluate_llm_diff(
        diff,
        _make_finding("app.js", 10, 10, "injection.xss"),
        repo,
    )
    assert decision.allowed is True


def test_policy_denies_wrong_file(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.js").write_text("el.innerHTML = user\n", encoding="utf-8")

    diff = (
        "--- a/other.js\n"
        "+++ b/other.js\n"
        "@@ -1,1 +1,1 @@\n"
        "-el.innerHTML = user\n"
        "+el.textContent = user\n"
    )
    decision = evaluate_llm_diff(
        diff,
        _make_finding("app.js", 1, 1, "injection.xss"),
        repo,
    )
    assert decision.allowed is False
    assert "file" in decision.reason


def test_policy_denies_disallowed_addition(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hi')\n", encoding="utf-8")

    diff = (
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,1 +1,1 @@\n"
        "-print('hi')\n"
        "+import bcrypt\n"
    )
    decision = evaluate_llm_diff(
        diff,
        _make_finding("app.py", 1, 1, "injection.xss"),
        repo,
    )
    assert decision.allowed is False
    assert "disallowed" in decision.reason
