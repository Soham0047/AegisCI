import json
import os
import subprocess
from pathlib import Path
from typing import Any

import typer

from guardian.data.extract_python import extract_python_samples
from guardian.data.extract_ts import extract_ts_samples
from guardian.data.labels import attach_weak_labels, build_label_index, load_labels
from guardian.data.schema import Sample
from guardian.data.split import parse_split, split_samples
from guardian.data.validate import validate_jsonl

app = typer.Typer(add_completion=False)

SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    ".mypy_cache",
    ".pytest_cache",
    "__pycache__",
    "site-packages",
    "node_modules",
    "dist",
    "build",
}


def _iter_repo_files(repo_root: Path, extensions: set[str], max_files: int | None):
    count = 0
    for root, dirs, files in os.walk(repo_root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for filename in files:
            if Path(filename).suffix not in extensions:
                continue
            yield Path(root) / filename
            count += 1
            if max_files and count >= max_files:
                return


def _get_commit(repo_root: Path, commit_mode: str) -> str:
    if commit_mode == "workdir":
        return "WORKDIR"
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()
    except Exception:
        return "WORKDIR"


def _write_jsonl(path: Path, samples: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for sample in samples:
            handle.write(json.dumps(sample, ensure_ascii=True) + "\n")


def _build_language_samples(
    repo_paths: list[Path],
    language: str,
    context_lines: int,
    max_files_per_repo: int | None,
    commit_mode: str,
    label_index: dict[tuple[str | None, str], list[dict[str, Any]]],
    tool_versions: dict[str, Any],
) -> list[dict[str, Any]]:
    samples: list[dict[str, Any]] = []
    extensions = {".py"} if language == "python" else {".ts", ".tsx", ".js", ".jsx"}
    extractor = extract_python_samples if language == "python" else extract_ts_samples

    for repo_root in repo_paths:
        repo_id = f"local/{repo_root.name}"
        commit = _get_commit(repo_root, commit_mode)
        repo_samples: list[dict[str, Any]] = []
        for file_path in _iter_repo_files(repo_root, extensions, max_files_per_repo):
            repo_samples.extend(
                extractor(
                    file_path=file_path,
                    repo_root=repo_root,
                    repo_id=repo_id,
                    commit=commit,
                    context_lines=context_lines,
                    tool_versions=tool_versions,
                )
            )
        attach_weak_labels(repo_samples, label_index, repo_id)

        for sample in repo_samples:
            validated = Sample.model_validate(sample).model_dump()
            samples.append(validated)

    samples.sort(key=lambda item: item["sample_id"])
    return samples


@app.command()
def build(
    repos_dir: Path = typer.Option(Path("data/repos")),
    out_dir: Path = typer.Option(Path("datasets")),
    languages: str = typer.Option("python,ts"),
    context_lines: int = typer.Option(10),
    max_files_per_repo: int | None = typer.Option(None),
    seed: int = typer.Option(1337),
    split: str = typer.Option("0.8,0.1,0.1"),
    labels_path: Path | None = typer.Option(None),
    commit_mode: str = typer.Option("git"),
    validate: bool = typer.Option(False),
) -> None:
    if commit_mode not in {"git", "workdir"}:
        typer.echo("commit-mode must be 'git' or 'workdir'")
        raise typer.Exit(code=1)
    if not repos_dir.exists():
        typer.echo(f"Repos dir not found: {repos_dir}")
        raise typer.Exit(code=1)

    repo_paths = [p for p in repos_dir.iterdir() if p.is_dir()]
    if not repo_paths:
        typer.echo("No repos found in repos-dir; nothing to build.")
        raise typer.Exit(code=0)

    language_list = [lang.strip() for lang in languages.split(",") if lang.strip()]
    for lang in language_list:
        if lang not in {"python", "ts"}:
            typer.echo(f"Unsupported language: {lang}")
            raise typer.Exit(code=1)

    split_ratios = parse_split(split)

    labels: list[dict[str, Any]] = []
    tool_versions: dict[str, Any] = {}
    if labels_path:
        labels, tool_versions = load_labels(labels_path)
    label_index = build_label_index(labels)

    for lang in language_list:
        samples = _build_language_samples(
            repo_paths=repo_paths,
            language=lang,
            context_lines=context_lines,
            max_files_per_repo=max_files_per_repo,
            commit_mode=commit_mode,
            label_index=label_index,
            tool_versions=tool_versions,
        )

        lang_dir = out_dir / lang
        _write_jsonl(lang_dir / "all.jsonl", samples)
        buckets = split_samples(samples, seed=seed, split=split_ratios)
        for name, items in buckets.items():
            _write_jsonl(lang_dir / f"{name}.jsonl", items)

        if validate:
            for name in ("all", "train", "val", "test"):
                _, errors = validate_jsonl(lang_dir / f"{name}.jsonl")
                if errors:
                    raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
