import json
import sys
import requests

# Usage:
# python scripts/post_report.py report.json org/repo 12 abc123

if len(sys.argv) != 5:
    print("Usage: python scripts/post_report.py <report.json> <repo> <pr_number> <sha>")
    raise SystemExit(1)

path, repo, pr_number, sha = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
raw = json.loads(open(path, "r", encoding="utf-8").read())

payload = {"repo": repo, "pr_number": pr_number, "sha": sha, "raw": raw}
resp = requests.post("http://localhost:8000/api/v1/reports", json=payload, timeout=30)
print(resp.status_code, resp.text)
