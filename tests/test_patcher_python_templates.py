from pathlib import Path

from patcher.patcher import generate_patches


def _finding(path: str, line: int, rule_id: str, safe_fix: str | None = None) -> dict:
    data = {
        "finding_id": f"{path}:{line}:{rule_id}",
        "rule": {"rule_id": rule_id, "category": rule_id, "name": rule_id},
        "location": {"filepath": path, "start_line": line, "end_line": line},
        "source": "bandit",
    }
    if safe_fix:
        data["extra"] = {"safe_fix": safe_fix}
    return data


def test_subprocess_shell_true_removal(tmp_path: Path) -> None:
    path = tmp_path / "app.py"
    path.write_text("import subprocess\nsubprocess.run(['ls'], shell=True)\n", encoding="utf-8")
    findings = [_finding("app.py", 2, "B602")]

    bundle = generate_patches(tmp_path, findings)
    new_text = bundle.patched_files["app.py"]
    assert "shell=True" not in new_text
    assert "subprocess.run(['ls'])" in new_text


def test_subprocess_shell_true_rejects_string(tmp_path: Path) -> None:
    path = tmp_path / "app.py"
    path.write_text("import subprocess\nsubprocess.run('ls', shell=True)\n", encoding="utf-8")
    findings = [_finding("app.py", 2, "B602")]

    bundle = generate_patches(tmp_path, findings)
    assert bundle.combined_diff == ""
    assert bundle.results[0].applied is False


def test_compare_digest_fix(tmp_path: Path) -> None:
    path = tmp_path / "auth.py"
    path.write_text("def check(a, b):\n    return a == b\n", encoding="utf-8")
    finding = _finding("auth.py", 2, "timing", safe_fix="compare_digest")

    bundle = generate_patches(tmp_path, [finding])
    new_text = bundle.patched_files["auth.py"]
    assert "hmac.compare_digest(a, b)" in new_text
    assert "import hmac" in new_text


def test_secrets_token_choice(tmp_path: Path) -> None:
    path = tmp_path / "token.py"
    path.write_text("import random\n\ntoken = random.choice(chars)\n", encoding="utf-8")
    finding = _finding("token.py", 3, "rand", safe_fix="secrets_token")

    bundle = generate_patches(tmp_path, [finding])
    new_text = bundle.patched_files["token.py"]
    assert "secrets.choice(chars)" in new_text
    assert "import secrets" in new_text


def test_secrets_token_random_fstring(tmp_path: Path) -> None:
    path = tmp_path / "token.py"
    path.write_text('import random\n\ntoken = f"{random.random()}"\n', encoding="utf-8")
    finding = _finding("token.py", 3, "rand", safe_fix="secrets_token")

    bundle = generate_patches(tmp_path, [finding])
    new_text = bundle.patched_files["token.py"]
    assert "secrets.token_urlsafe(32)" in new_text
    assert "import secrets" in new_text
