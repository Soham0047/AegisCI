import subprocess
from typing import List


def _run(cmd: list[str]) -> str:
    return subprocess.check_output(cmd, text=True).strip()


def get_changed_files(base_ref: str) -> List[str]:
    """Files changed between origin/<base_ref> and HEAD."""
    diff_cmd = ["git", "diff", "--name-only", f"origin/{base_ref}...HEAD"]
    output = _run(diff_cmd)
    if not output:
        return []
    return [line.strip() for line in output.splitlines() if line.strip()]
