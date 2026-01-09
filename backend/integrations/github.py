from __future__ import annotations

import json
import urllib.request
from typing import Any

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover - requests is optional
    requests = None


def create_or_update_comment(
    repo: str,
    pr_number: int,
    marker: str,
    body: str,
    token: str | None,
    dry_run: bool = False,
    base_url: str = "https://api.github.com",
    session: Any | None = None,
) -> dict[str, Any]:
    if dry_run:
        return {
            "action": "create",
            "repo": repo,
            "pr_number": pr_number,
            "marker": marker,
            "body": body,
        }
    if not token:
        raise RuntimeError("GitHub token is required")

    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    comment = _find_existing_comment(repo, pr_number, marker, headers, base_url, session)
    if comment:
        comment_id = comment["id"]
        payload = {"body": body}
        _request(
            "PATCH",
            f"{base_url}/repos/{repo}/issues/comments/{comment_id}",
            headers,
            payload,
            session,
        )
        return {"action": "update", "comment_id": comment_id, "repo": repo}

    payload = {"body": body}
    _request(
        "POST",
        f"{base_url}/repos/{repo}/issues/{pr_number}/comments",
        headers,
        payload,
        session,
    )
    return {"action": "create", "repo": repo}


def _find_existing_comment(
    repo: str,
    pr_number: int,
    marker: str,
    headers: dict[str, str],
    base_url: str,
    session: Any | None,
) -> dict[str, Any] | None:
    page = 1
    while True:
        url = f"{base_url}/repos/{repo}/issues/{pr_number}/comments?per_page=100&page={page}"
        data = _request("GET", url, headers, None, session)
        if not isinstance(data, list) or not data:
            return None
        for item in data:
            if marker in (item.get("body") or ""):
                return item
        page += 1


def _request(
    method: str,
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any] | None,
    session: Any | None,
) -> Any:
    if session is None and requests is not None:
        session = requests

    if session is not None:
        response = session.request(method, url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        return response.json() if response.text else {}

    data = json.dumps(payload or {}).encode("utf-8") if payload else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=30) as resp:
        content = resp.read().decode("utf-8")
    return json.loads(content) if content else {}
