from guardian.data.mapping import build_span_index, match_by_enclosing_span, match_nearest_span


def test_mapping_enclosing_and_nearest() -> None:
    samples = [
        {
            "sample_id": "class1",
            "repo": "local/repo",
            "filepath": "file.py",
            "function_span": {"start_line": 1, "end_line": 20},
        },
        {
            "sample_id": "method1",
            "repo": "local/repo",
            "filepath": "file.py",
            "function_span": {"start_line": 5, "end_line": 10},
        },
        {
            "sample_id": "func2",
            "repo": "local/repo",
            "filepath": "file.py",
            "function_span": {"start_line": 30, "end_line": 40},
        },
    ]
    index = build_span_index(samples)

    assert match_by_enclosing_span(index, "local/repo", "file.py", 6) == "method1"
    assert match_by_enclosing_span(index, "local/repo", "file.py", 15) == "class1"
    assert match_by_enclosing_span(index, "local/repo", "file.py", 25) is None

    assert match_nearest_span(index, "local/repo", "file.py", 25, max_distance=5) == "func2"
    assert match_nearest_span(index, "local/repo", "file.py", 25, max_distance=3) is None
