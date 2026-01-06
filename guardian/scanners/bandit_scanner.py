import json
import subprocess
from typing import Any, Dict, List


def run_bandit(py_files: List[str]) -> Dict[str, Any]:
    """Run Bandit on provided Python files. Returns JSON-like dict."""
    if not py_files:
        return {"results": [], "errors": []}

    cmd = ["bandit", "-f", "json", "-q", *py_files]
    try:
        out = subprocess.check_output(cmd, text=True)
        return json.loads(out)
    except FileNotFoundError:
        return {"results": [], "errors": ["bandit not installed"]}
    except subprocess.CalledProcessError as e:
        # Bandit exits non-zero on findings; still may output JSON.
        try:
            return json.loads(e.output or "{}")
        except Exception:
            return {"results": [], "errors": [f"bandit failed: {e}"]}
