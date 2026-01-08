from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ml.graphs.python_graph import build_python_graphs
from ml.graphs.ts_graph import build_ts_graphs


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


def _graph_to_dict(graph) -> dict[str, Any]:
    return {
        "node_type_ids": graph.node_type_ids.tolist(),
        "ident_hash_ids": graph.ident_hash_ids.tolist(),
        "literal_flags": graph.literal_flags.tolist(),
        "edge_index": graph.edge_index.tolist(),
        "edge_type_ids": graph.edge_type_ids.tolist(),
        "node_depth": graph.node_depth.tolist() if graph.node_depth is not None else None,
        "span_line": graph.span_line.tolist() if graph.span_line is not None else None,
        "metadata": graph.metadata,
    }


def build_graphs(args: argparse.Namespace) -> None:
    items = _load_jsonl(Path(args.input))
    total = 0
    success = 0
    truncated = 0
    output_rows: list[dict[str, Any]] = []

    for item in items:
        code = _get_code(item)
        if not code:
            total += 1
            continue
        total += 1
        if args.lang == "python":
            graphs = build_python_graphs(code, max_nodes=args.max_nodes, max_edges=args.max_edges)
        else:
            graphs = build_ts_graphs(
                code,
                language=args.lang,
                max_nodes=args.max_nodes,
                max_edges=args.max_edges,
            )
        if not graphs:
            continue
        graph = graphs[0]
        success += 1
        if graph.metadata.get("truncated"):
            truncated += 1
        output_rows.append(
            {
                "sample_id": item.get("sample_id"),
                "label": item.get("label"),
                "verdict": item.get("verdict"),
                "category": item.get("category"),
                "graph": _graph_to_dict(graph),
            }
        )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        for row in output_rows:
            handle.write(json.dumps(row, ensure_ascii=True) + "\n")

    report = {
        "input": args.input,
        "lang": args.lang,
        "total": total,
        "success": success,
        "success_rate": (success / total) if total else 0.0,
        "truncated": truncated,
        "max_nodes": args.max_nodes,
        "max_edges": args.max_edges,
    }
    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build program graphs from JSONL dataset")
    parser.add_argument("--input", required=True)
    parser.add_argument(
        "--lang",
        required=True,
        choices=["python", "ts", "javascript", "typescript", "tsx", "jsx"],
    )
    parser.add_argument("--out", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--max-nodes", type=int, default=2048)
    parser.add_argument("--max-edges", type=int, default=8192)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    build_graphs(args)


if __name__ == "__main__":
    main()
