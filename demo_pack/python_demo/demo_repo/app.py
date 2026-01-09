"""Demo application with a command injection vulnerability (B602)."""

import subprocess


def list_files(directory: str) -> str:
    """List files in a directory. VULNERABLE: uses shell=True with user input."""
    result = subprocess.run(f"ls {directory}", shell=True, capture_output=True, text=True)
    return result.stdout


def safe_echo(message: str) -> str:
    """Echo a message safely (no vulnerability here)."""
    return f"Echo: {message}"


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        print(list_files(sys.argv[1]))
    else:
        print(list_files("."))
