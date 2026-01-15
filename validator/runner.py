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
    allow_network: bool,
) -> tuple[int, str, str, float]:
    start = time.time()
    docker_cmd = [
        "docker",
        "run",
        "--rm",
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
    if not allow_network:
        docker_cmd.insert(3, "--network=none")
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
            changed_paths = _extract_paths_from_patch(patch_text)

            mode = args.mode
            if mode == "auto":
                inferred = _infer_mode_from_patch(patch_text)
                if inferred != "auto":
                    mode = inferred

            baseline_results: list[dict[str, Any]] | None = None
            if args.baseline:
                baseline_results = _run_steps(
                    args,
                    worktree,
                    changed_paths,
                    out_dir,
                    mode,
                    label_prefix="baseline",
                )
                if baseline_results is None:
                    return _report_failure(out_dir, "baseline", "", "baseline run failed")

            code, out, err = _run(["git", "apply", "--check", str(patch_path)], cwd=worktree)
            if code != 0:
                return _report_failure(out_dir, "apply_check", out, err)
            code, out, err = _run(["git", "apply", str(patch_path)], cwd=worktree)
            if code != 0:
                return _report_failure(out_dir, "apply", out, err)

            results = _run_steps(
                args,
                worktree,
                changed_paths,
                out_dir,
                mode,
                label_prefix="",
            )
            if results is None:
                return _report_failure(out_dir, "validation", "", "validation run failed")

            results_failed = any(entry.get("code", 0) != 0 for entry in results)
            if baseline_results is not None:
                comparison = _compare_results(baseline_results, results)
                if comparison["new_failures"]:
                    return _report_failure(
                        out_dir,
                        "regression",
                        "",
                        "baseline failures present; patch introduced new failures",
                        results,
                    )
            elif results_failed:
                return _report_failure(
                    out_dir,
                    "validation",
                    "",
                    "validation steps failed",
                    results,
                )

            report = {
                "status": "validated",
                "run_id": run_id,
                "commit": args.commit,
                "steps": results,
            }
            if baseline_results is not None:
                report["baseline_steps"] = baseline_results
                report["baseline_comparison"] = _compare_results(baseline_results, results)
            (out_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
            return report
        finally:
            _run(["git", "worktree", "remove", "--force", str(worktree)], cwd=repo_path)


def _python_steps(project_root: Path, worktree: Path, run_mypy: bool) -> list[tuple[str, str]]:
    steps: list[tuple[str, str]] = []
    prefix = _cmd_prefix(worktree, project_root)
    if project_root.joinpath("pyproject.toml").exists():
        steps.append(("pip_install", f"{prefix} && python -m pip install -e '.[dev]'"))
    elif project_root.joinpath("requirements.txt").exists():
        steps.append(("pip_install", f"{prefix} && python -m pip install -r requirements.txt"))
    steps.append(("ruff", f"{prefix} && python -m ruff check ."))
    steps.append(("pytest", f"{prefix} && pytest"))
    if run_mypy:
        steps.append(("mypy", f"{prefix} && python -m mypy ."))
    return steps


def _node_steps(project_root: Path, worktree: Path) -> list[tuple[str, str]]:
    steps: list[tuple[str, str]] = []
    prefix = _cmd_prefix(worktree, project_root)
    pkg = _load_package_json(project_root)
    if project_root.joinpath("package-lock.json").exists():
        steps.append(("npm_install", f"{prefix} && npm ci"))
    else:
        steps.append(("npm_install", f"{prefix} && npm install"))

    scripts = (pkg.get("scripts") or {}) if isinstance(pkg, dict) else {}
    if "lint" in scripts:
        steps.append(("eslint", f"{prefix} && npm run lint"))
    else:
        steps.append(("eslint", f"{prefix} && npx eslint ."))
    if project_root.joinpath("tsconfig.json").exists():
        steps.append(("tsc", f"{prefix} && npx tsc --noEmit"))

    deps = pkg.get("dependencies") or {}
    dev_deps = pkg.get("devDependencies") or {}
    if "jest" in deps or "jest" in dev_deps or "test" in scripts:
        steps.append(("jest", f"{prefix} && npx jest"))
    return steps


def _run_steps(
    args: argparse.Namespace,
    worktree: Path,
    changed_paths: list[str],
    out_dir: Path,
    mode: str,
    label_prefix: str,
) -> list[dict[str, Any]] | None:
    _ensure_image(args.image, Path(args.dockerfile))
    has_python, has_node = _detect_modes(worktree)

    python_roots = _find_project_roots(
        worktree, changed_paths, ["pyproject.toml", "requirements.txt", "setup.cfg"]
    )
    node_roots = _find_project_roots(worktree, changed_paths, ["package.json"])
    if mode in {"auto", "python", "both"} and not python_roots and has_python:
        python_roots = [worktree]
    if mode in {"auto", "ts", "both"} and not node_roots and has_node:
        node_roots = [worktree]

    steps: list[tuple[str, str]] = []
    if mode in {"auto", "python", "both"}:
        for root in python_roots:
            steps.extend(_python_steps(root, worktree, args.run_mypy))
    if mode in {"auto", "ts", "both"}:
        for root in node_roots:
            steps.extend(_node_steps(root, worktree))

    lint_mode = args.lint_mode
    if lint_mode == "off":
        steps = [step for step in steps if step[0] != "ruff"]
    elif lint_mode == "changed":
        python_files = [
            path
            for path in changed_paths
            if path.endswith(".py") and worktree.joinpath(path).exists()
        ]
        if not python_files:
            steps = [step for step in steps if step[0] != "ruff"]
        else:
            steps = [
                (
                    "ruff",
                    "cd /repo && python -m ruff check " + " ".join(python_files),
                )
                if name == "ruff"
                else (name, cmd)
                for name, cmd in steps
            ]

    if args.test_mode == "off":
        steps = [step for step in steps if step[0] not in {"pytest", "jest"}]

    results: list[dict[str, Any]] = []
    total_start = time.time()
    for name, cmd in steps:
        if time.time() - total_start > args.timeout_seconds:
            return None
        code, out, err, duration = _docker_run(
            args.image, worktree, cmd, args.timeout_seconds, args.allow_network
        )
        suffix = f"{label_prefix}_{name}" if label_prefix else name
        (out_dir / f"{suffix}.out").write_text(out, encoding="utf-8")
        (out_dir / f"{suffix}.err").write_text(err, encoding="utf-8")
        results.append({"step": name, "code": code, "duration": duration, "command": cmd})
        if code != 0:
            return results
    return results


def _compare_results(
    baseline: list[dict[str, Any]],
    patched: list[dict[str, Any]],
) -> dict[str, Any]:
    baseline_map = {entry["step"]: entry for entry in baseline}
    patched_map = {entry["step"]: entry for entry in patched}
    new_failures: list[str] = []
    for step, patched_entry in patched_map.items():
        if patched_entry.get("code", 0) != 0 and baseline_map.get(step, {}).get("code", 0) == 0:
            new_failures.append(step)
    return {"new_failures": new_failures}


def _extract_paths_from_patch(patch_text: str) -> list[str]:
    paths: set[str] = set()
    for line in patch_text.splitlines():
        if line.startswith("diff --git "):
            parts = line.split()
            if len(parts) >= 4:
                path = parts[3]
                if path.startswith("b/"):
                    path = path[2:]
                paths.add(path)
        elif line.startswith("+++ "):
            path = line[4:].strip()
            if path.startswith("b/"):
                path = path[2:]
            if path and path != "/dev/null":
                paths.add(path)
    return sorted(paths)


def _find_project_roots(worktree: Path, paths: list[str], markers: list[str]) -> list[Path]:
    roots: list[Path] = []
    for path_str in paths:
        path = worktree / path_str
        current = path if path.is_dir() else path.parent
        while True:
            if any(current.joinpath(marker).exists() for marker in markers):
                if current not in roots:
                    roots.append(current)
                break
            if current == worktree:
                break
            current = current.parent
    return sorted(roots, key=lambda p: p.as_posix())


def _cmd_prefix(worktree: Path, project_root: Path) -> str:
    rel = project_root.relative_to(worktree)
    if rel.as_posix() == ".":
        return "cd /repo"
    return f"cd /repo/{rel.as_posix()}"


def _infer_mode_from_patch(patch_text: str) -> str:
    paths = _extract_paths_from_patch(patch_text)
    if not paths:
        return "auto"

    has_py = any(path.endswith(".py") for path in paths)
    has_ts = any(path.endswith(ext) for path in paths for ext in (".js", ".jsx", ".ts", ".tsx"))

    if has_py and has_ts:
        return "both"
    if has_py:
        return "python"
    if has_ts:
        return "ts"
    return "auto"


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
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument(
        "--lint-mode",
        default="strict",
        choices=["strict", "changed", "off"],
        help="Lint scope for Python: strict=repo, changed=only changed files, off=skip.",
    )
    parser.add_argument(
        "--test-mode",
        default="strict",
        choices=["strict", "off"],
        help="Test scope: strict=run tests, off=skip tests.",
    )
    parser.add_argument(
        "--baseline",
        action="store_true",
        help="Run baseline checks before applying patch and allow if no new failures.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    report = run_validation(args)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
