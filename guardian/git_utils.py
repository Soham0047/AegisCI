import subprocess


def _run(cmd: list[str], check: bool = True) -> str:
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL).strip()
    except subprocess.CalledProcessError:
        if check:
            raise
        return ""


def get_changed_files(base_ref: str) -> list[str]:
    """Files changed between origin/<base_ref> (or local base_ref) and HEAD."""
    # Try origin/base_ref first, fall back to local base_ref
    remote_ref = f"origin/{base_ref}"
    local_ref = base_ref

    # Check if remote ref exists
    if _run(["git", "rev-parse", "--verify", remote_ref], check=False):
        ref = remote_ref
    elif _run(["git", "rev-parse", "--verify", local_ref], check=False):
        # For initial commits, compare against empty tree or list all files
        ref = local_ref
    else:
        # No base ref found, scan all tracked files
        output = _run(["git", "ls-files"])
        if not output:
            return []
        return [line.strip() for line in output.splitlines() if line.strip()]

    diff_cmd = ["git", "diff", "--name-only", f"{ref}...HEAD"]
    output = _run(diff_cmd, check=False)

    # If diff fails (e.g., same commit), list all files
    if not output:
        output = _run(["git", "ls-files"])

    if not output:
        return []
    return [line.strip() for line in output.splitlines() if line.strip()]
