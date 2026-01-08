import json
import sys

import requests

# Usage:
# python scripts/post_report.py report.json org/repo 12 abc123 [base_ref]

if len(sys.argv) not in (5, 6):
    print("Usage: python scripts/post_report.py <report.json> <repo> <pr_number> <sha> [base_ref]")
    raise SystemExit(1)

path, repo, pr_number, sha = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
base_ref = sys.argv[5] if len(sys.argv) == 6 else "main"
raw = json.loads(open(path, encoding="utf-8").read())

payload = {
    "repo": repo,
    "pr_number": pr_number,
    "commit_sha": sha,
    "base_ref": base_ref,
    "report": raw,
    "tool_versions": {},
}
resp = requests.post("http://localhost:8000/api/v1/reports", json=payload, timeout=30)
print(resp.status_code, resp.text)
