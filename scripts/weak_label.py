import json
import shlex
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import typer

from guardian.data.schema import Sample
from guardian.data.weak_labeling import (
    load_tool_outputs,
    map_findings_to_samples,
    write_tool_outputs_for_repo,
)

app = typer.Typer(add_completion=False)


def _list_repos(repos_dir: Path) -> list[Path]:
    if not repos_dir.exists():
        typer.echo(f"Repos dir not found: {repos_dir}")
        raise typer.Exit(code=1)
    return [p for p in repos_dir.iterdir() if p.is_dir()]


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True) + "\n")


def _load_samples(
    dataset_paths: list[Path],
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    samples: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    for path in dataset_paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            sample = json.loads(line)
            Sample.model_validate(sample)
            samples.append(sample)
            by_id[sample["sample_id"]] = sample
    return samples, by_id


def _default_dataset_paths(datasets_dir: Path) -> list[Path]:
    paths: list[Path] = []
    for lang in ("python", "ts"):
        path = datasets_dir / lang / "all.jsonl"
        if path.exists():
            paths.append(path)
    return paths


def _update_dataset_files(
    dataset_paths: list[Path],
    labels_by_id: dict[str, list[dict[str, Any]]],
    versions_by_id: dict[str, dict[str, Any]],
) -> None:
    for path in dataset_paths:
        updated: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            sample = json.loads(line)
            sample_id = sample["sample_id"]
            sample["weak_labels"] = labels_by_id.get(sample_id, [])
            meta = sample.get("metadata") or {}
            meta.setdefault("tool_versions", {})
            tool_versions = versions_by_id.get(sample_id)
            if tool_versions:
                meta["tool_versions"].update(tool_versions)
            sample["metadata"] = meta
            updated.append(sample)
        _write_jsonl(path, updated)


@app.command("run-tools")
def run_tools(
    repos_dir: Path = typer.Option(Path("data/repos")),
    out_dir: Path = typer.Option(Path("data/tool_outputs")),
    bandit_args: str = typer.Option("-q -f json"),
    semgrep_args: str = typer.Option("--json"),
    semgrep_config: str = typer.Option("p/ci"),
    max_files_per_repo: int | None = typer.Option(None),
    reuse: bool = typer.Option(False),
    workers: int = typer.Option(1),
) -> None:
    repos = _list_repos(repos_dir)
    if not repos:
        typer.echo("No repos found.")
        raise typer.Exit(code=0)

    bandit_args_list = shlex.split(bandit_args)
    semgrep_args_list = shlex.split(semgrep_args)

    if workers <= 1:
        for repo_root in repos:
            write_tool_outputs_for_repo(
                repo_root=repo_root,
                out_dir=out_dir,
                bandit_args=bandit_args_list,
                semgrep_args=semgrep_args_list,
                semgrep_config=semgrep_config,
                max_files=max_files_per_repo,
                reuse=reuse,
            )
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(
                    write_tool_outputs_for_repo,
                    repo_root,
                    out_dir,
                    bandit_args_list,
                    semgrep_args_list,
                    semgrep_config,
                    max_files_per_repo,
                    reuse,
                ): repo_root
                for repo_root in repos
            }
            for future in as_completed(futures):
                future.result()


@app.command("map")
def map_labels(
    tool_outputs: Path = typer.Option(Path("data/tool_outputs")),
    datasets_dir: Path = typer.Option(Path("datasets")),
    dataset: list[Path] = typer.Option(None),
    repos_dir: Path = typer.Option(Path("data/repos")),
    out: Path = typer.Option(Path("datasets/weak_labels.jsonl")),
    update_dataset: bool = typer.Option(False),
    max_distance: int = typer.Option(3),
) -> None:
    dataset_paths = dataset or _default_dataset_paths(datasets_dir)
    if not dataset_paths:
        typer.echo("No dataset files found.")
        raise typer.Exit(code=1)

    samples, _ = _load_samples(dataset_paths)

    labels_by_id: dict[str, list[dict[str, Any]]] = {}
    versions_by_id: dict[str, dict[str, Any]] = {}
    totals = {"total": 0, "mapped": 0}

    for repo_out in tool_outputs.iterdir():
        if not repo_out.is_dir():
            continue
        repo_root = repos_dir / repo_out.name
        if not repo_root.exists():
            repo_root = repo_out

        findings, tool_versions = load_tool_outputs(repo_root, tool_outputs)
        repo_id = tool_versions.get("repo") or f"local/{repo_out.name}"
        mapped, counts = map_findings_to_samples(
            samples, findings, repo_id=repo_id, max_distance=max_distance
        )
        totals["total"] += counts["total"]
        totals["mapped"] += counts["mapped"]

        for sample_id, labels in mapped.items():
            labels_by_id.setdefault(sample_id, []).extend(labels)
            versions_by_id.setdefault(sample_id, {}).update(
                {k: v for k, v in tool_versions.items() if k in {"bandit", "semgrep"}}
            )

        if counts["total"]:
            rate = (counts["mapped"] / counts["total"]) * 100
            typer.echo(f"{repo_id}: {counts['mapped']}/{counts['total']} mapped ({rate:.1f}%)")

    overall_rate = (totals["mapped"] / totals["total"] * 100) if totals["total"] else 0.0
    typer.echo(f"overall: {totals['mapped']}/{totals['total']} mapped ({overall_rate:.1f}%)")

    all_sample_ids = sorted({sample["sample_id"] for sample in samples})
    records = [
        {
            "sample_id": sample_id,
            "weak_labels": labels_by_id.get(sample_id, []),
            "tool_versions": versions_by_id.get(sample_id, {}),
        }
        for sample_id in all_sample_ids
    ]
    _write_jsonl(out, records)

    if update_dataset:
        _update_dataset_files(dataset_paths, labels_by_id, versions_by_id)


@app.command("label")
def label(
    repos_dir: Path = typer.Option(Path("data/repos")),
    tool_outputs: Path = typer.Option(Path("data/tool_outputs")),
    datasets_dir: Path = typer.Option(Path("datasets")),
    bandit_args: str = typer.Option("-q -f json"),
    semgrep_args: str = typer.Option("--json"),
    semgrep_config: str = typer.Option("p/ci"),
    max_files_per_repo: int | None = typer.Option(None),
    reuse: bool = typer.Option(False),
    workers: int = typer.Option(1),
    update_dataset: bool = typer.Option(False),
    max_distance: int = typer.Option(3),
) -> None:
    run_tools(
        repos_dir=repos_dir,
        out_dir=tool_outputs,
        bandit_args=bandit_args,
        semgrep_args=semgrep_args,
        semgrep_config=semgrep_config,
        max_files_per_repo=max_files_per_repo,
        reuse=reuse,
        workers=workers,
    )
    map_labels(
        tool_outputs=tool_outputs,
        datasets_dir=datasets_dir,
        dataset=[],
        repos_dir=repos_dir,
        out=datasets_dir / "weak_labels.jsonl",
        update_dataset=update_dataset,
        max_distance=max_distance,
    )


if __name__ == "__main__":
    app()
