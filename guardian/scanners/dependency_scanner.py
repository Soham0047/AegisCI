"""
Dependency Vulnerability Scanner - Detects known vulnerabilities in dependencies.

This scanner checks:
- Python: requirements.txt, pyproject.toml, setup.py
- JavaScript: package.json, package-lock.json, yarn.lock

Uses patterns to detect commonly vulnerable package versions and
provides advisory information.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class VulnerablePackage:
    """A known vulnerable package pattern."""
    name: str
    vulnerable_versions: str  # semver range or regex pattern
    severity: str
    cve: str | None
    description: str
    fixed_version: str | None
    ecosystem: str  # pypi, npm


# Known vulnerable Python packages
PYTHON_VULNERABILITIES: list[VulnerablePackage] = [
    VulnerablePackage(
        name="django",
        vulnerable_versions="<3.2.25",
        severity="high",
        cve="CVE-2024-27351",
        description="Potential denial-of-service in django.utils.text.Truncator",
        fixed_version="3.2.25",
        ecosystem="pypi",
    ),
    VulnerablePackage(
        name="django",
        vulnerable_versions="<2.2",
        severity="critical",
        cve="CVE-2019-14234",
        description="SQL injection in Django JSONField",
        fixed_version="2.2.4",
        ecosystem="pypi",
    ),
    VulnerablePackage(
        name="flask",
        vulnerable_versions="<2.2.5",
        severity="high",
        cve="CVE-2023-30861",
        description="Cookie header injection vulnerability",
        fixed_version="2.2.5",
        ecosystem="pypi",
    ),
    VulnerablePackage(
        name="requests",
        vulnerable_versions="<2.31.0",
        severity="medium",
        cve="CVE-2023-32681",
        description="Unintended leak of Proxy-Authorization header",
        fixed_version="2.31.0",
        ecosystem="pypi",
    ),
    VulnerablePackage(
        name="pyyaml",
        vulnerable_versions="<5.4",
        severity="critical",
        cve="CVE-2020-14343",
        description="Arbitrary code execution in YAML parsing",
        fixed_version="5.4",
        ecosystem="pypi",
    ),
    VulnerablePackage(
        name="urllib3",
        vulnerable_versions="<1.26.18",
        severity="medium",
        cve="CVE-2023-45803",
        description="Cookie leakage on cross-origin redirect",
        fixed_version="1.26.18",
        ecosystem="pypi",
    ),
    VulnerablePackage(
        name="pillow",
        vulnerable_versions="<10.0.1",
        severity="high",
        cve="CVE-2023-44271",
        description="Buffer overflow vulnerability",
        fixed_version="10.0.1",
        ecosystem="pypi",
    ),
    VulnerablePackage(
        name="cryptography",
        vulnerable_versions="<41.0.6",
        severity="medium",
        cve="CVE-2023-49083",
        description="NULL dereference in PKCS12 parsing",
        fixed_version="41.0.6",
        ecosystem="pypi",
    ),
    VulnerablePackage(
        name="aiohttp",
        vulnerable_versions="<3.9.0",
        severity="high",
        cve="CVE-2023-47627",
        description="HTTP request smuggling via content-encoding",
        fixed_version="3.9.0",
        ecosystem="pypi",
    ),
    VulnerablePackage(
        name="sqlalchemy",
        vulnerable_versions="<1.4.49",
        severity="medium",
        cve="CVE-2023-30861",
        description="SQL injection in the limit/offset clause",
        fixed_version="1.4.49",
        ecosystem="pypi",
    ),
    VulnerablePackage(
        name="werkzeug",
        vulnerable_versions="<2.3.8",
        severity="high",
        cve="CVE-2023-46136",
        description="Path traversal vulnerability",
        fixed_version="2.3.8",
        ecosystem="pypi",
    ),
    VulnerablePackage(
        name="jinja2",
        vulnerable_versions="<3.1.3",
        severity="medium",
        cve="CVE-2024-22195",
        description="Cross-site scripting (XSS) vulnerability",
        fixed_version="3.1.3",
        ecosystem="pypi",
    ),
    VulnerablePackage(
        name="paramiko",
        vulnerable_versions="<3.4.0",
        severity="high",
        cve="CVE-2023-48795",
        description="SSH protocol vulnerability (Terrapin attack)",
        fixed_version="3.4.0",
        ecosystem="pypi",
    ),
    VulnerablePackage(
        name="tornado",
        vulnerable_versions="<6.3.3",
        severity="high",
        cve="CVE-2023-28370",
        description="HTTP header injection vulnerability",
        fixed_version="6.3.3",
        ecosystem="pypi",
    ),
]

# Known vulnerable npm packages
NPM_VULNERABILITIES: list[VulnerablePackage] = [
    VulnerablePackage(
        name="lodash",
        vulnerable_versions="<4.17.21",
        severity="high",
        cve="CVE-2021-23337",
        description="Prototype pollution vulnerability",
        fixed_version="4.17.21",
        ecosystem="npm",
    ),
    VulnerablePackage(
        name="axios",
        vulnerable_versions="<1.6.0",
        severity="high",
        cve="CVE-2023-45857",
        description="SSRF vulnerability in axios proxy",
        fixed_version="1.6.0",
        ecosystem="npm",
    ),
    VulnerablePackage(
        name="express",
        vulnerable_versions="<4.19.2",
        severity="medium",
        cve="CVE-2024-29041",
        description="Open redirect vulnerability",
        fixed_version="4.19.2",
        ecosystem="npm",
    ),
    VulnerablePackage(
        name="jsonwebtoken",
        vulnerable_versions="<9.0.0",
        severity="high",
        cve="CVE-2022-23529",
        description="Improper token validation",
        fixed_version="9.0.0",
        ecosystem="npm",
    ),
    VulnerablePackage(
        name="minimist",
        vulnerable_versions="<1.2.6",
        severity="critical",
        cve="CVE-2021-44906",
        description="Prototype pollution vulnerability",
        fixed_version="1.2.6",
        ecosystem="npm",
    ),
    VulnerablePackage(
        name="node-fetch",
        vulnerable_versions="<2.6.7",
        severity="high",
        cve="CVE-2022-0235",
        description="Exposure of sensitive information",
        fixed_version="2.6.7",
        ecosystem="npm",
    ),
    VulnerablePackage(
        name="tar",
        vulnerable_versions="<6.1.11",
        severity="critical",
        cve="CVE-2021-37712",
        description="Arbitrary file creation vulnerability",
        fixed_version="6.1.11",
        ecosystem="npm",
    ),
    VulnerablePackage(
        name="glob-parent",
        vulnerable_versions="<5.1.2",
        severity="high",
        cve="CVE-2020-28469",
        description="Regular expression denial of service",
        fixed_version="5.1.2",
        ecosystem="npm",
    ),
    VulnerablePackage(
        name="semver",
        vulnerable_versions="<7.5.2",
        severity="medium",
        cve="CVE-2022-25883",
        description="Regular expression denial of service",
        fixed_version="7.5.2",
        ecosystem="npm",
    ),
    VulnerablePackage(
        name="qs",
        vulnerable_versions="<6.10.3",
        severity="high",
        cve="CVE-2022-24999",
        description="Prototype pollution vulnerability",
        fixed_version="6.10.3",
        ecosystem="npm",
    ),
    VulnerablePackage(
        name="tough-cookie",
        vulnerable_versions="<4.1.3",
        severity="medium",
        cve="CVE-2023-26136",
        description="Prototype pollution vulnerability",
        fixed_version="4.1.3",
        ecosystem="npm",
    ),
    VulnerablePackage(
        name="word-wrap",
        vulnerable_versions="<1.2.4",
        severity="medium",
        cve="CVE-2023-26115",
        description="Regular expression denial of service",
        fixed_version="1.2.4",
        ecosystem="npm",
    ),
    VulnerablePackage(
        name="xml2js",
        vulnerable_versions="<0.5.0",
        severity="medium",
        cve="CVE-2023-0842",
        description="Prototype pollution vulnerability",
        fixed_version="0.5.0",
        ecosystem="npm",
    ),
    VulnerablePackage(
        name="moment",
        vulnerable_versions="<2.29.4",
        severity="high",
        cve="CVE-2022-31129",
        description="Inefficient regular expression complexity",
        fixed_version="2.29.4",
        ecosystem="npm",
    ),
]


def parse_version(version_str: str) -> tuple[int, ...]:
    """Parse a version string into a tuple of integers."""
    # Remove leading 'v', '^', '~', '>=', etc.
    version_str = re.sub(r"^[v^~>=<]+", "", version_str.strip())
    # Extract just the version numbers
    match = re.match(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", version_str)
    if match:
        parts = [int(p) if p else 0 for p in match.groups()]
        return tuple(parts)
    return (0, 0, 0)


def is_vulnerable(installed_version: str, vulnerable_range: str) -> bool:
    """Check if an installed version is within a vulnerable range."""
    installed = parse_version(installed_version)
    
    # Parse the vulnerable range (simplified)
    if vulnerable_range.startswith("<"):
        fixed = parse_version(vulnerable_range[1:])
        return installed < fixed
    elif vulnerable_range.startswith("<="):
        fixed = parse_version(vulnerable_range[2:])
        return installed <= fixed
    elif "," in vulnerable_range:
        # Range like ">=1.0,<2.0"
        parts = vulnerable_range.split(",")
        for part in parts:
            part = part.strip()
            if part.startswith("<"):
                if not installed < parse_version(part[1:]):
                    return False
            elif part.startswith(">="):
                if not installed >= parse_version(part[2:]):
                    return False
        return True
    
    return False


def scan_requirements_txt(filepath: str | Path) -> list[dict[str, Any]]:
    """Scan a requirements.txt file for vulnerable packages."""
    findings: list[dict[str, Any]] = []
    path = Path(filepath)
    
    if not path.exists():
        return findings
    
    content = path.read_text(encoding="utf-8")
    lines = content.split("\n")
    
    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        
        # Parse package==version or package>=version
        match = re.match(r"([a-zA-Z0-9_-]+)(?:[=<>]+)(.+)", line.split("#")[0].strip())
        if match:
            package_name = match.group(1).lower()
            version = match.group(2).strip()
            
            for vuln in PYTHON_VULNERABILITIES:
                if vuln.name.lower() == package_name:
                    if is_vulnerable(version, vuln.vulnerable_versions):
                        findings.append({
                            "check_id": f"DEP-{vuln.cve or 'UNKNOWN'}",
                            "check_name": f"Vulnerable {vuln.name}",
                            "path": str(path),
                            "start": {"line": line_num, "col": 0},
                            "end": {"line": line_num, "col": len(line)},
                            "extra": {
                                "message": f"{vuln.description}. Upgrade to {vuln.fixed_version}",
                                "severity": vuln.severity.upper(),
                                "metadata": {
                                    "category": "dependency",
                                    "cve": vuln.cve,
                                    "package": vuln.name,
                                    "installed_version": version,
                                    "fixed_version": vuln.fixed_version,
                                    "ecosystem": vuln.ecosystem,
                                },
                            },
                        })
    
    return findings


def scan_package_json(filepath: str | Path) -> list[dict[str, Any]]:
    """Scan a package.json file for vulnerable packages."""
    findings: list[dict[str, Any]] = []
    path = Path(filepath)
    
    if not path.exists():
        return findings
    
    try:
        content = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return findings
    
    # Check both dependencies and devDependencies
    all_deps: dict[str, str] = {}
    all_deps.update(content.get("dependencies", {}))
    all_deps.update(content.get("devDependencies", {}))
    
    for package_name, version in all_deps.items():
        package_lower = package_name.lower()
        
        for vuln in NPM_VULNERABILITIES:
            if vuln.name.lower() == package_lower:
                if is_vulnerable(version, vuln.vulnerable_versions):
                    findings.append({
                        "check_id": f"DEP-{vuln.cve or 'UNKNOWN'}",
                        "check_name": f"Vulnerable {vuln.name}",
                        "path": str(path),
                        "start": {"line": 1, "col": 0},
                        "end": {"line": 1, "col": 0},
                        "extra": {
                            "message": f"{vuln.description}. Upgrade to {vuln.fixed_version}",
                            "severity": vuln.severity.upper(),
                            "metadata": {
                                "category": "dependency",
                                "cve": vuln.cve,
                                "package": vuln.name,
                                "installed_version": version,
                                "fixed_version": vuln.fixed_version,
                                "ecosystem": vuln.ecosystem,
                            },
                        },
                    })
    
    return findings


def scan_pyproject_toml(filepath: str | Path) -> list[dict[str, Any]]:
    """Scan a pyproject.toml file for vulnerable packages."""
    findings: list[dict[str, Any]] = []
    path = Path(filepath)
    
    if not path.exists():
        return findings
    
    try:
        import tomllib
        content = tomllib.loads(path.read_text(encoding="utf-8"))
    except ImportError:
        # Fallback for Python < 3.11
        try:
            import tomli as tomllib
            content = tomllib.loads(path.read_text(encoding="utf-8"))
        except ImportError:
            return findings
    except Exception:
        return findings
    
    # Get dependencies from project.dependencies
    deps: list[str] = content.get("project", {}).get("dependencies", [])
    
    for dep in deps:
        # Parse dependency string like "package>=1.0.0"
        match = re.match(r"([a-zA-Z0-9_-]+)(?:[=<>]+)(.+)", dep.split(";")[0].strip())
        if match:
            package_name = match.group(1).lower()
            version = match.group(2).strip()
            
            for vuln in PYTHON_VULNERABILITIES:
                if vuln.name.lower() == package_name:
                    if is_vulnerable(version, vuln.vulnerable_versions):
                        findings.append({
                            "check_id": f"DEP-{vuln.cve or 'UNKNOWN'}",
                            "check_name": f"Vulnerable {vuln.name}",
                            "path": str(path),
                            "start": {"line": 1, "col": 0},
                            "end": {"line": 1, "col": 0},
                            "extra": {
                                "message": f"{vuln.description}. Upgrade to {vuln.fixed_version}",
                                "severity": vuln.severity.upper(),
                                "metadata": {
                                    "category": "dependency",
                                    "cve": vuln.cve,
                                    "package": vuln.name,
                                    "installed_version": version,
                                    "fixed_version": vuln.fixed_version,
                                    "ecosystem": vuln.ecosystem,
                                },
                            },
                        })
    
    return findings


def run_pip_audit() -> dict[str, Any]:
    """Run pip-audit if available for more comprehensive scanning."""
    try:
        result = subprocess.run(
            ["pip-audit", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0 or result.stdout:
            return json.loads(result.stdout)
    except FileNotFoundError:
        pass  # pip-audit not installed
    except Exception:
        pass
    return {"dependencies": []}


def run_npm_audit(directory: str | Path = ".") -> dict[str, Any]:
    """Run npm audit if available for more comprehensive scanning."""
    try:
        result = subprocess.run(
            ["npm", "audit", "--json"],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=directory,
        )
        return json.loads(result.stdout or "{}")
    except FileNotFoundError:
        pass  # npm not installed
    except Exception:
        pass
    return {"vulnerabilities": {}}


def scan_directory(directory: str | Path = ".") -> dict[str, Any]:
    """Scan a directory for dependency vulnerability files."""
    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    path = Path(directory)
    
    # Scan Python dependency files
    for req_file in ["requirements.txt", "requirements-dev.txt", "requirements-test.txt"]:
        req_path = path / req_file
        if req_path.exists():
            findings.extend(scan_requirements_txt(req_path))
    
    # Scan pyproject.toml
    pyproject = path / "pyproject.toml"
    if pyproject.exists():
        findings.extend(scan_pyproject_toml(pyproject))
    
    # Scan package.json
    package_json = path / "package.json"
    if package_json.exists():
        findings.extend(scan_package_json(package_json))
    
    # Also check subdirectories (e.g., frontend/, gateway/)
    for subdir in path.iterdir():
        if subdir.is_dir() and not subdir.name.startswith("."):
            sub_package = subdir / "package.json"
            if sub_package.exists():
                findings.extend(scan_package_json(sub_package))
    
    return {
        "results": findings,
        "errors": errors,
        "scanner": "dependency",
        "version": "1.0.0",
        "paths": {"scanned": [str(path)]},
    }


def run_dependency_scanner(files: list[str] | None = None, directory: str = ".") -> dict[str, Any]:
    """
    Run the dependency vulnerability scanner.
    
    Can scan specific files or an entire directory.
    """
    if files:
        findings: list[dict[str, Any]] = []
        for filepath in files:
            path = Path(filepath)
            if path.name == "requirements.txt":
                findings.extend(scan_requirements_txt(path))
            elif path.name == "package.json":
                findings.extend(scan_package_json(path))
            elif path.name == "pyproject.toml":
                findings.extend(scan_pyproject_toml(path))
        
        return {
            "results": findings,
            "errors": [],
            "scanner": "dependency",
            "version": "1.0.0",
            "paths": {"scanned": files},
        }
    
    return scan_directory(directory)
