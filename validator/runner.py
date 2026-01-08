from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
import time
from hashlib import sha1
from pathlib import Path
from typing import Any


def _run(
    cmd: list[str],
    cwd: Path | None = None,
    timeout: int | None = None,
) -> tuple[int, str, str]:
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _detect_modes(repo_path: Path) -> tuple[bool, bool]:
    has_python = (
        repo_path.joinpath("pyproject.toml").exists()
        or repo_path.joinpath("requirements.txt").exists()
    )
    has_node = repo_path.joinpath("package.json").exists()
    return has_python, has_node


def _load_package_json(repo_path: Path) -> dict[str, Any]:
    try:
        return json.loads(repo_path.joinpath("package.json").read_text(encoding="utf-8"))
    except Exception:
        return {}


def _build_image(tag: str, dockerfile: Path) -> None:
    code, out, err = _run(
        ["docker", "build", "-t", tag, "-f", str(dockerfile), "."], cwd=dockerfile.parent
    )
    if code != 0:
        raise RuntimeError(f"docker build failed: {err or out}")


def _ensure_image(tag: str, dockerfile: Path) -> None:
    code, _, _ = _run(["docker", "image", "inspect", tag])
    if code != 0:
        _build_image(tag, dockerfile)


def _docker_run(
    image: str,
    repo_path: Path,
    command: str,
    timeout: int,
) -> tuple[int, str, str, float]:
    start = time.time()
    docker_cmd = [
        "docker",
        "run",
        "--rm",
        "--network=none",
        "--cpus=2",
        "--memory=4g",
        "--pids-limit=256",
        "-v",
        f"{repo_path}:/repo",
        image,
        "bash",
        "-lc",
        command,
    ]
    code, out, err = _run(docker_cmd, timeout=timeout)
    return code, out, err, time.time() - start


def run_validation(args: argparse.Namespace) -> dict[str, Any]:
    repo_path = Path(args.repo).resolve()
    if not repo_path.exists():
        raise SystemExit("repo path does not exist")

    if shutil.which("git") is None:
        raise SystemExit("git is required")
    if shutil.which("docker") is None:
        raise SystemExit("docker is required")

    patch_text = Path(args.patch).read_text(encoding="utf-8")
    run_id = sha1((args.commit + patch_text).encode("utf-8")).hexdigest()[:12]
    out_dir = Path("artifacts/validation") / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="validator_") as tmpdir:
        worktree = Path(tmpdir) / "worktree"
        code, out, err = _run(
            ["git", "worktree", "add", "--detach", str(worktree), args.commit], cwd=repo_path
        )
        if code != 0:
            return _report_failure(out_dir, "worktree", out, err)

        try:
            patch_path = Path(tmpdir) / "patch.diff"
            patch_path.write_text(patch_text, encoding="utf-8")
            code, out, err = _run(["git", "apply", "--check", str(patch_path)], cwd=worktree)
            if code != 0:
                return _report_failure(out_dir, "apply_check", out, err)
            code, out, err = _run(["git", "apply", str(patch_path)], cwd=worktree)
            if code != 0:
                return _report_failure(out_dir, "apply", out, err)

            _ensure_image(args.image, Path(args.dockerfile))
            has_python, has_node = _detect_modes(worktree)
            mode = args.mode
            steps: list[tuple[str, str]] = []

            if mode in {"auto", "python", "both"} and has_python:
                steps.extend(_python_steps(worktree, args.run_mypy))
            if mode in {"auto", "ts", "both"} and has_node:
                steps.extend(_node_steps(worktree))

            results = []
            total_start = time.time()
            for name, cmd in steps:
                if time.time() - total_start > args.timeout_seconds:
                    return _report_failure(out_dir, name, "", "overall timeout")
                code, out, err, duration = _docker_run(
                    args.image, worktree, cmd, args.timeout_seconds
                )
                (out_dir / f"{name}.out").write_text(out, encoding="utf-8")
                (out_dir / f"{name}.err").write_text(err, encoding="utf-8")
                results.append({"step": name, "code": code, "duration": duration, "command": cmd})
                if code != 0:
                    return _report_failure(out_dir, name, out, err, results)

            report = {
                "status": "validated",
                "run_id": run_id,
                "commit": args.commit,
                "steps": results,
            }
            (out_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
            return report
        finally:
            _run(["git", "worktree", "remove", "--force", str(worktree)], cwd=repo_path)


def _python_steps(repo_path: Path, run_mypy: bool) -> list[tuple[str, str]]:
    steps: list[tuple[str, str]] = []
    if repo_path.joinpath("pyproject.toml").exists():
        steps.append(("pip_install", "cd /repo && python -m pip install -e '.[dev]'"))
    elif repo_path.joinpath("requirements.txt").exists():
        steps.append(("pip_install", "cd /repo && python -m pip install -r requirements.txt"))
    steps.append(("ruff", "cd /repo && python -m ruff check ."))
    steps.append(("pytest", "cd /repo && pytest"))
    if run_mypy:
        steps.append(("mypy", "cd /repo && python -m mypy ."))
    return steps


def _node_steps(repo_path: Path) -> list[tuple[str, str]]:
    steps: list[tuple[str, str]] = []
    pkg = _load_package_json(repo_path)
    if repo_path.joinpath("package-lock.json").exists():
        steps.append(("npm_install", "cd /repo && npm ci"))
    else:
        steps.append(("npm_install", "cd /repo && npm install"))

    scripts = (pkg.get("scripts") or {}) if isinstance(pkg, dict) else {}
    if "lint" in scripts:
        steps.append(("eslint", "cd /repo && npm run lint"))
    else:
        steps.append(("eslint", "cd /repo && npx eslint ."))
    if repo_path.joinpath("tsconfig.json").exists():
        steps.append(("tsc", "cd /repo && npx tsc --noEmit"))

    deps = pkg.get("dependencies") or {}
    dev_deps = pkg.get("devDependencies") or {}
    if "jest" in deps or "jest" in dev_deps or "test" in scripts:
        steps.append(("jest", "cd /repo && npx jest"))
    return steps


def _report_failure(
    out_dir: Path,
    step: str,
    out: str,
    err: str,
    results: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    report = {
        "status": "rejected",
        "failed_step": step,
        "reason": err.strip() or out.strip() or "unknown failure",
        "steps": results or [],
    }
    (out_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate patches in a sandbox container.")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--patch", required=True)
    parser.add_argument("--mode", default="auto", choices=["auto", "python", "ts", "both"])
    parser.add_argument("--run-mypy", action="store_true")
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument("--image", default="securedev-guardian-validator:latest")
    parser.add_argument("--dockerfile", default="docker/validator.Dockerfile")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    report = run_validation(args)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
