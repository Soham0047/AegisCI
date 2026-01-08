from backend.integrations.github import create_or_update_comment


def test_github_dry_run_payload() -> None:
    result = create_or_update_comment(
        repo="org/repo",
        pr_number=1,
        marker="<!-- PATCH-COPILOT:job1 -->",
        body="test",
        token="SECRET",
        dry_run=True,
    )
    assert result["action"] == "create"
    assert "SECRET" not in str(result)
