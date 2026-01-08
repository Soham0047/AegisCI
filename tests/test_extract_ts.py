from pathlib import Path

from guardian.data.extract_ts import extract_ts_samples


def test_extract_ts_samples(tmp_path: Path) -> None:
    source = "\n".join(
        [
            "function foo() {",
            "  return 1;",
            "}",
            "const bar = () => {",
            "  return 2;",
            "};",
            "class Baz {",
            "  method() {",
            "    return 3;",
            "  }",
            "}",
            "",
        ]
    )
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    file_path = repo_root / "app.ts"
    file_path.write_text(source, encoding="utf-8")

    samples = extract_ts_samples(
        file_path=file_path,
        repo_root=repo_root,
        repo_id="local/repo",
        commit="WORKDIR",
        context_lines=1,
    )

    snippets = {sample["code_snippet"] for sample in samples}
    assert any("function foo" in snippet for snippet in snippets)
    assert any("const bar" in snippet for snippet in snippets)
    assert any("class Baz" in snippet for snippet in snippets)
