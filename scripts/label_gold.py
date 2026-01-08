import json
from pathlib import Path

import typer

from guardian.data.label_cli import (
    compute_stats,
    generate_selection,
    label_items,
    load_selected_items,
    parse_inputs,
)

app = typer.Typer(add_completion=False)


def _parse_severity_weights(raw: str) -> dict[str, int]:
    weights = {}
    for part in raw.split(","):
        if not part.strip():
            continue
        key, value = part.split("=")
        weights[key.strip().upper()] = int(value.strip())
    return weights


@app.command()
def label(
    inputs: str = typer.Option("datasets/python/all.jsonl,datasets/ts/all.jsonl"),
    selected: Path = typer.Option(Path("datasets/gold/selected_items.jsonl")),
    out: Path = typer.Option(Path("datasets/gold/gold_labels.jsonl")),
    annotator: str = typer.Option(...),
    resume: bool = typer.Option(True),
    max_items: int | None = typer.Option(None),
    show_context_lines: bool = typer.Option(True),
    pretty: bool = typer.Option(True),
    target_n: int = typer.Option(300),
    seed: int = typer.Option(1337),
    overlap_ratio: float = typer.Option(0.1),
    per_rule_cap: int = typer.Option(25),
    severity_weights: str = typer.Option("HIGH=3,MEDIUM=2,LOW=1,INFO=1"),
) -> None:
    input_paths = parse_inputs(inputs)
    if not selected.exists():
        generate_selection(
            inputs=input_paths,
            selected_path=selected,
            target_n=target_n,
            seed=seed,
            overlap_ratio=overlap_ratio,
            per_rule_cap=per_rule_cap,
            severity_weights=_parse_severity_weights(severity_weights),
        )

    items = load_selected_items(selected)
    labeled = label_items(
        items=items,
        out_path=out,
        annotator_id=annotator,
        resume=resume,
        max_items=max_items,
        show_context_lines=show_context_lines,
        pretty=pretty,
    )
    typer.echo(f"Labeled {labeled} items")


@app.command()
def stats(gold: Path = typer.Option(Path("datasets/gold/gold_labels.jsonl"))) -> None:
    if not gold.exists():
        typer.echo(f"Gold labels not found: {gold}")
        raise typer.Exit(code=1)
    data = compute_stats(gold)
    typer.echo(json.dumps(data, indent=2))


@app.command()
def select(
    inputs: str = typer.Option("datasets/python/all.jsonl,datasets/ts/all.jsonl"),
    selected: Path = typer.Option(Path("datasets/gold/selected_items.jsonl")),
    target_n: int = typer.Option(300),
    seed: int = typer.Option(1337),
    overlap_ratio: float = typer.Option(0.1),
    per_rule_cap: int = typer.Option(25),
    severity_weights: str = typer.Option("HIGH=3,MEDIUM=2,LOW=1,INFO=1"),
) -> None:
    input_paths = parse_inputs(inputs)
    selected_items = generate_selection(
        inputs=input_paths,
        selected_path=selected,
        target_n=target_n,
        seed=seed,
        overlap_ratio=overlap_ratio,
        per_rule_cap=per_rule_cap,
        severity_weights=_parse_severity_weights(severity_weights),
    )
    typer.echo(f"Wrote {len(selected_items)} items to {selected}")


if __name__ == "__main__":
    app()
