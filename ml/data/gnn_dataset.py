from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ml.graphs.python_graph import build_python_graphs
from ml.graphs.ts_graph import build_ts_graphs
from ml.train_transformer import _extract_categories, _extract_risk_label


@dataclass
class GraphSample:
    sample_id: str
    graph: Any
    risk_label: int
    category: str


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [json.loads(line) for line in lines]


def _get_code(item: dict[str, Any]) -> str:
    for key in ("code_snippet", "code", "snippet"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value
    tokens = item.get("tokens")
    if isinstance(tokens, list):
        return " ".join(str(tok) for tok in tokens)
    return ""


def _get_language(item: dict[str, Any], default_lang: str) -> str:
    language = item.get("language")
    if isinstance(language, str) and language.strip():
        return language.lower()
    filepath = item.get("filepath") or ""
    if isinstance(filepath, str) and filepath.endswith((".ts", ".tsx", ".js", ".jsx")):
        return "ts"
    return default_lang


def build_graph_samples(
    path: Path,
    max_nodes: int,
    max_edges: int,
    default_lang: str = "python",
) -> tuple[list[GraphSample], dict[str, int]]:
    items = _load_jsonl(path)
    samples: list[GraphSample] = []
    skipped = {"no_code": 0, "no_label": 0, "parse_fail": 0}

    for item in items:
        code = _get_code(item)
        if not code:
            skipped["no_code"] += 1
            continue

        categories = _extract_categories(item)
        if not categories:
            skipped["no_label"] += 1
            continue
        risk_label = _extract_risk_label(item)
        if risk_label is None or risk_label < 0:
            skipped["no_label"] += 1
            continue

        language = _get_language(item, default_lang=default_lang)
        if language.startswith("py"):
            graphs = build_python_graphs(code, max_nodes=max_nodes, max_edges=max_edges)
        else:
            graphs = build_ts_graphs(
                code, language=language, max_nodes=max_nodes, max_edges=max_edges
            )
        if not graphs:
            skipped["parse_fail"] += 1
            continue
        graph = graphs[0]
        samples.append(
            GraphSample(
                sample_id=item.get("sample_id", ""),
                graph=graph,
                risk_label=risk_label,
                category=categories[0],
            )
        )

    return samples, skipped
