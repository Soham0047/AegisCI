from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

from guardian.data.gold_schema import CATEGORY_VOCAB, FIX_TYPE_VOCAB, FindingRef, GoldLabel, SpanRef
from guardian.data.sampling import build_item_id, build_label_items, select_items
from guardian.data.schema import Sample


def parse_inputs(inputs: str) -> list[Path]:
    return [Path(p.strip()) for p in inputs.split(",") if p.strip()]


def load_samples(paths: list[Path]) -> list[dict[str, Any]]:
    samples: list[dict[str, Any]] = []
    for path in paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            sample = json.loads(line)
            Sample.model_validate(sample)
            samples.append(sample)
    return samples


def load_selected_items(path: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        items.append(json.loads(line))
    return items


def write_selected_items(path: Path, items: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for item in items:
            handle.write(json.dumps(item, ensure_ascii=True) + "\n")


def generate_selection(
    inputs: list[Path],
    selected_path: Path,
    target_n: int,
    seed: int,
    overlap_ratio: float,
    per_rule_cap: int,
    severity_weights: dict[str, int],
) -> list[dict[str, Any]]:
    samples = load_samples(inputs)
    items = build_label_items(samples)
    selected = select_items(
        items,
        target_n=target_n,
        seed=seed,
        overlap_ratio=overlap_ratio,
        per_rule_cap=per_rule_cap,
        severity_weights=severity_weights,
    )
    write_selected_items(selected_path, selected)
    return selected


def _label_key(sample_id: str, finding: dict[str, Any], annotator_id: str) -> str:
    return f"{build_item_id(sample_id, finding)}|{annotator_id}"


def load_labeled_keys(path: Path, annotator_id: str) -> set[str]:
    if not path.exists():
        return set()
    keys: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        label = GoldLabel.model_validate(json.loads(line))
        key = _label_key(label.sample_id, label.finding.model_dump(), label.annotator_id)
        keys.add(key)
    return keys


class PromptProvider:
    def __init__(self, console: Console):
        self.console = console

    def _choose_from_list(self, prompt: str, options: tuple[str, ...]) -> str:
        self.console.print("\n".join([f"{idx + 1}. {opt}" for idx, opt in enumerate(options)]))
        while True:
            choice = Prompt.ask(prompt, default="1")
            if choice.lower() in {"q", "quit"}:
                raise KeyboardInterrupt
            if choice.isdigit() and 1 <= int(choice) <= len(options):
                return options[int(choice) - 1]
            self.console.print("Invalid choice. Try again.")

    def get_response(self, item: dict[str, Any]) -> dict[str, Any] | None:
        verdict = Prompt.ask("Verdict", choices=["TP", "FP", "UNCERTAIN"], default="TP")
        category = self._choose_from_list("Category number", CATEGORY_VOCAB)
        fix_type = self._choose_from_list("Fix type number", FIX_TYPE_VOCAB)
        notes = Prompt.ask("Notes (optional)", default="")
        return {
            "verdict": verdict,
            "category": category,
            "fix_type": fix_type,
            "notes": notes.strip() or None,
        }


def render_item(console: Console, item: dict[str, Any], show_context_lines: bool) -> None:
    finding = item.get("finding") or {}
    repo = item.get("repo") or "unknown"
    filepath = item.get("filepath") or "unknown"
    language = item.get("language") or "unknown"
    span = item.get("span") or {}
    message = (finding.get("message") or "").strip()
    header_lines = [
        f"{repo} | {filepath} | {language}",
        f"span {span}",
        (
            "finding "
            f"{finding.get('source')}:{finding.get('rule_id')} "
            f"{finding.get('severity')}/{finding.get('confidence')} "
            f"line {finding.get('line')}"
        ),
    ]
    if message:
        header_lines.append(f"message: {message}")
    console.rule("Label Item")
    console.print(Panel("\n".join(header_lines), title="Details", style="bold"))
    if show_context_lines:
        if item.get("context_before"):
            console.print(Panel(item["context_before"], title="Context Before", style="dim"))
    console.print(Panel(item.get("code_snippet") or "", title="Code Snippet"))
    if show_context_lines:
        if item.get("context_after"):
            console.print(Panel(item["context_after"], title="Context After", style="dim"))


def label_items(
    items: list[dict[str, Any]],
    out_path: Path,
    annotator_id: str,
    resume: bool,
    max_items: int | None,
    show_context_lines: bool,
    pretty: bool,
    input_provider: Callable[[dict[str, Any]], dict[str, Any] | None] | None = None,
) -> int:
    console = Console()
    labeled_keys = load_labeled_keys(out_path, annotator_id) if resume else set()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    provider = input_provider
    if provider is None:
        prompt_provider = PromptProvider(console)
        provider = prompt_provider.get_response

    labeled = 0
    with out_path.open("a", encoding="utf-8") as handle:
        for item in items:
            if max_items is not None and labeled >= max_items:
                break
            sample_id = item.get("sample_id")
            if not isinstance(sample_id, str):
                continue
            finding_obj = item.get("finding")
            finding: dict[str, Any] = finding_obj if isinstance(finding_obj, dict) else {}
            if not finding:
                continue
            key = _label_key(sample_id, finding, annotator_id)
            if resume and key in labeled_keys:
                continue
            if pretty:
                render_item(console, item, show_context_lines)
            response = provider(item)
            if response is None:
                break
            language = item.get("language")
            if language not in {"python", "ts"}:
                continue
            repo = item.get("repo")
            if not isinstance(repo, str):
                continue
            commit = item.get("commit")
            if not isinstance(commit, str):
                continue
            filepath = item.get("filepath")
            if not isinstance(filepath, str):
                continue
            span_obj = item.get("span")
            if not isinstance(span_obj, dict):
                continue
            span_ref = SpanRef.model_validate(span_obj)
            finding_ref = FindingRef.model_validate(finding)
            label = GoldLabel(
                sample_id=sample_id,
                language=language,
                repo=repo,
                commit=commit,
                filepath=filepath,
                span=span_ref,
                finding=finding_ref,
                verdict=response["verdict"],
                category=response["category"],
                fix_type=response["fix_type"],
                annotator_id=annotator_id,
                labeled_at=datetime.utcnow().isoformat(),
                notes=response.get("notes"),
                duplicate_group=item.get("duplicate_group"),
                schema_version="1.0",
            )
            handle.write(json.dumps(label.model_dump(), ensure_ascii=True) + "\n")
            handle.flush()
            labeled_keys.add(key)
            labeled += 1
    return labeled


def compute_stats(path: Path) -> dict[str, Any]:
    counts: dict[str, Any] = {
        "by_source": {},
        "by_verdict": {},
        "by_category": {},
        "by_rule_id": {},
    }
    labels: list[GoldLabel] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        labels.append(GoldLabel.model_validate(json.loads(line)))

    for label in labels:
        source = label.finding.source
        counts["by_source"][source] = counts["by_source"].get(source, 0) + 1
        counts["by_verdict"][label.verdict] = counts["by_verdict"].get(label.verdict, 0) + 1
        counts["by_category"][label.category] = counts["by_category"].get(label.category, 0) + 1
        rule_id = label.finding.rule_id
        counts["by_rule_id"][rule_id] = counts["by_rule_id"].get(rule_id, 0) + 1

    agreement_total = 0
    agreement_match = 0
    groups: dict[str, list[GoldLabel]] = {}
    for label in labels:
        if not label.duplicate_group:
            continue
        groups.setdefault(label.duplicate_group, []).append(label)
    for group_labels in groups.values():
        if len(group_labels) < 2:
            continue
        agreement_total += 1
        verdicts = {label.verdict for label in group_labels}
        if len(verdicts) == 1:
            agreement_match += 1

    counts["agreement"] = {
        "groups": agreement_total,
        "matches": agreement_match,
        "percent": (agreement_match / agreement_total * 100) if agreement_total else 0.0,
    }
    return counts
