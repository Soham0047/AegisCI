import json
from pathlib import Path

from guardian.data.gold_schema import GoldLabel
from guardian.data.label_cli import label_items, write_selected_items


class StaticProvider:
    def __init__(self):
        self.calls = 0

    def __call__(self, item):
        self.calls += 1
        return {
            "verdict": "TP",
            "category": "unsafe.exec",
            "fix_type": "no_fix_needed",
            "notes": None,
        }


def _make_item(item_id: str) -> dict:
    return {
        "item_id": item_id,
        "sample_id": f"sample-{item_id}",
        "language": "python",
        "repo": "local/repo",
        "commit": "WORKDIR",
        "filepath": "file.py",
        "span": {"start_line": 1, "end_line": 2, "start_col": 0, "end_col": 0},
        "code_snippet": "def foo():\n    return 1",
        "context_before": "",
        "context_after": "",
        "finding": {
            "source": "bandit",
            "rule_id": f"R{item_id}",
            "severity": "HIGH",
            "confidence": "MEDIUM",
            "message": "msg",
            "line": 1,
        },
        "duplicate_group": None,
    }


def test_label_cli_resume(tmp_path: Path) -> None:
    selected_path = tmp_path / "selected_items.jsonl"
    out_path = tmp_path / "gold_labels.jsonl"

    items = [_make_item(str(i)) for i in range(5)]
    write_selected_items(selected_path, items)

    provider = StaticProvider()
    label_items(
        items=items,
        out_path=out_path,
        annotator_id="alice",
        resume=True,
        max_items=3,
        show_context_lines=False,
        pretty=False,
        input_provider=provider,
    )

    label_items(
        items=items,
        out_path=out_path,
        annotator_id="alice",
        resume=True,
        max_items=None,
        show_context_lines=False,
        pretty=False,
        input_provider=provider,
    )

    lines = out_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 5
    for line in lines:
        GoldLabel.model_validate(json.loads(line))
