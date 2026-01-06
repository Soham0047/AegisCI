import json
import subprocess
from typing import Any, Dict, List


def run_semgrep(files: List[str], config: str = "p/ci") -> Dict[str, Any]:
    """Run Semgrep on provided files. Returns JSON-like dict."""
    if not files:
        return {"results": [], "errors": []}

    cmd = ["semgrep", "--config", config, "--json", *files]
    try:
        out = subprocess.check_output(cmd, text=True)
        return json.loads(out)
    except FileNotFoundError:
        return {"results": [], "errors": ["semgrep not installed"]}
    except subprocess.CalledProcessError as e:
        # Semgrep exits non-zero on findings; still may output JSON.
        try:
            return json.loads(e.output or "{}")
        except Exception:
            return {"results": [], "errors": [f"semgrep failed: {e}"]}
