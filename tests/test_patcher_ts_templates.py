from pathlib import Path

from patcher.patcher import generate_patches


def _finding(path: str, line: int, safe_fix: str) -> dict:
    return {
        "finding_id": f"{path}:{line}:{safe_fix}",
        "rule": {"rule_id": safe_fix, "category": safe_fix, "name": safe_fix},
        "location": {"filepath": path, "start_line": line, "end_line": line},
        "source": "semgrep",
        "extra": {"safe_fix": safe_fix},
    }


def test_innerhtml_to_textcontent(tmp_path: Path) -> None:
    path = tmp_path / "app.js"
    path.write_text("el.innerHTML = userInput;\n", encoding="utf-8")
    finding = _finding("app.js", 1, "untrusted_to_innerhtml")

    bundle = generate_patches(tmp_path, [finding])
    new_text = bundle.patched_files["app.js"]
    assert "textContent" in new_text


def test_escape_regexp_helper_added(tmp_path: Path) -> None:
    path = tmp_path / "app.ts"
    path.write_text("const re = new RegExp(userInput);\n", encoding="utf-8")
    finding = _finding("app.ts", 1, "escape_regexp")

    bundle = generate_patches(tmp_path, [finding])
    new_text = bundle.patched_files["app.ts"]
    assert "escapeRegExp(userInput)" in new_text
    assert "function escapeRegExp" in new_text


def test_json_parse_eval(tmp_path: Path) -> None:
    path = tmp_path / "app.js"
    path.write_text("const obj = eval('(' + payload + ')');\n", encoding="utf-8")
    finding = _finding("app.js", 1, "json_parse_eval")

    bundle = generate_patches(tmp_path, [finding])
    new_text = bundle.patched_files["app.js"]
    assert "JSON.parse(payload)" in new_text
