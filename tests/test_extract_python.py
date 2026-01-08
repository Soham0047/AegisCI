from pathlib import Path

from guardian.data.extract_python import extract_python_samples


def test_extract_python_samples(tmp_path: Path) -> None:
    source = "\n".join(
        [
            "# before",
            "def foo():",
            "    return 1",
            "",
            "async def bar():",
            "    if True:",
            "        return 2",
            "",
            "class Baz:",
            "    def method(self):",
            "        return 3",
            "",
        ]
    )
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    file_path = repo_root / "app.py"
    file_path.write_text(source, encoding="utf-8")

    samples = extract_python_samples(
        file_path=file_path,
        repo_root=repo_root,
        repo_id="local/repo",
        commit="WORKDIR",
        context_lines=1,
    )

    snippets = {sample["code_snippet"] for sample in samples}
    assert any("def foo()" in snippet for snippet in snippets)
    assert any("async def bar()" in snippet for snippet in snippets)
    assert any("class Baz" in snippet for snippet in snippets)

    foo_sample = next(sample for sample in samples if "def foo()" in sample["code_snippet"])
    assert foo_sample["function_span"]["start_line"] == 2
    assert foo_sample["function_span"]["end_line"] == 3
    assert foo_sample["context_before"] == "# before"
    assert foo_sample["context_after"] == ""
    assert foo_sample["metadata"]["cyclomatic_complexity"] == 1
