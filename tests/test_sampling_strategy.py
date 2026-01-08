from guardian.data.sampling import select_items


def _make_item(item_id: str, rule_id: str, severity: str, source: str, line: int) -> dict:
    return {
        "item_id": item_id,
        "sample_id": f"sample-{item_id}",
        "language": "python",
        "repo": "local/repo",
        "commit": "WORKDIR",
        "filepath": "file.py",
        "span": {"start_line": 1, "end_line": 20, "start_col": 0, "end_col": 0},
        "code_snippet": "def foo():\n    return 1",
        "context_before": "",
        "context_after": "",
        "finding": {
            "source": source,
            "rule_id": rule_id,
            "severity": severity,
            "confidence": "LOW" if severity == "LOW" else "HIGH",
            "message": "msg",
            "line": line,
        },
        "duplicate_group": None,
    }


def test_sampling_deterministic_and_overlap() -> None:
    items = []
    for idx in range(10):
        rule_id = "R1" if idx < 6 else "R2"
        severity = "HIGH" if idx % 2 == 0 else "LOW"
        source = "bandit" if idx % 3 == 0 else "semgrep"
        items.append(_make_item(str(idx), rule_id, severity, source, line=idx + 1))

    selected1 = select_items(
        items,
        target_n=6,
        seed=123,
        overlap_ratio=0.2,
        per_rule_cap=2,
        severity_weights={"HIGH": 3, "LOW": 1},
    )
    selected2 = select_items(
        items,
        target_n=6,
        seed=123,
        overlap_ratio=0.2,
        per_rule_cap=2,
        severity_weights={"HIGH": 3, "LOW": 1},
    )
    assert [item["item_id"] for item in selected1] == [item["item_id"] for item in selected2]

    overlap_groups = [item["duplicate_group"] for item in selected1 if item["duplicate_group"]]
    assert len(set(overlap_groups)) == 1  # 0.2 * 6 -> 1 overlap group
    assert len(overlap_groups) == 2

    counts = {}
    for item in {item["item_id"]: item for item in selected1}.values():
        rule_id = item["finding"]["rule_id"]
        counts[rule_id] = counts.get(rule_id, 0) + 1
    assert all(count <= 2 for count in counts.values())
