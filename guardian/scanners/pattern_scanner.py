"""
Code Pattern Scanner - Detects dangerous code patterns and security smells.

This scanner uses AST and regex analysis to detect:
- Dangerous function calls (eval, exec, pickle.loads, etc.)
- Insecure configurations
- Missing security headers
- Hardcoded values that should be configurable
- Deprecated or insecure APIs
- Input validation issues
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class PatternRule:
    """A pattern-based detection rule."""
    rule_id: str
    name: str
    pattern: re.Pattern[str] | None
    severity: str
    category: str
    description: str
    remediation: str
    cwe: str
    owasp: str | None = None
    languages: list[str] | None = None  # None means all languages


# Python-specific dangerous patterns
PYTHON_PATTERNS: list[PatternRule] = [
    # Dangerous function calls
    PatternRule(
        rule_id="PATTERN-PY-001",
        name="eval() usage",
        pattern=re.compile(r"\beval\s*\("),
        severity="critical",
        category="injection",
        description="eval() can execute arbitrary Python code, leading to RCE",
        remediation="Use ast.literal_eval() for literal evaluation or avoid dynamic code execution",
        cwe="CWE-95",
        owasp="A03:2021",
        languages=["python"],
    ),
    PatternRule(
        rule_id="PATTERN-PY-002",
        name="exec() usage",
        pattern=re.compile(r"\bexec\s*\("),
        severity="critical",
        category="injection",
        description="exec() can execute arbitrary Python code, leading to RCE",
        remediation="Avoid exec(). If dynamic execution is needed, use a sandboxed environment",
        cwe="CWE-95",
        owasp="A03:2021",
        languages=["python"],
    ),
    PatternRule(
        rule_id="PATTERN-PY-003",
        name="pickle.loads() usage",
        pattern=re.compile(r"\bpickle\.loads?\s*\("),
        severity="critical",
        category="deserialization",
        description="pickle.load() can deserialize malicious objects leading to RCE",
        remediation="Use JSON or other safe serialization formats. Never unpickle untrusted data",
        cwe="CWE-502",
        owasp="A08:2021",
        languages=["python"],
    ),
    PatternRule(
        rule_id="PATTERN-PY-004",
        name="yaml.load() without SafeLoader",
        pattern=re.compile(r"\byaml\.load\s*\([^)]*\)(?!\s*,\s*Loader\s*=\s*(?:yaml\.)?SafeLoader)"),
        severity="high",
        category="deserialization",
        description="yaml.load() without SafeLoader can deserialize malicious objects",
        remediation="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
        cwe="CWE-502",
        owasp="A08:2021",
        languages=["python"],
    ),
    PatternRule(
        rule_id="PATTERN-PY-005",
        name="shell=True in subprocess",
        pattern=re.compile(r"subprocess\.\w+\s*\([^)]*shell\s*=\s*True"),
        severity="high",
        category="injection",
        description="shell=True allows shell injection if user input is included",
        remediation="Use shell=False and pass arguments as a list",
        cwe="CWE-78",
        owasp="A03:2021",
        languages=["python"],
    ),
    PatternRule(
        rule_id="PATTERN-PY-006",
        name="os.system() usage",
        pattern=re.compile(r"\bos\.system\s*\("),
        severity="high",
        category="injection",
        description="os.system() is vulnerable to shell injection",
        remediation="Use subprocess.run() with shell=False and a list of arguments",
        cwe="CWE-78",
        owasp="A03:2021",
        languages=["python"],
    ),
    PatternRule(
        rule_id="PATTERN-PY-007",
        name="MD5 hashing",
        pattern=re.compile(r"\bhashlib\.md5\s*\("),
        severity="medium",
        category="crypto",
        description="MD5 is cryptographically broken and should not be used for security",
        remediation="Use SHA-256 or stronger hash functions (hashlib.sha256)",
        cwe="CWE-327",
        owasp="A02:2021",
        languages=["python"],
    ),
    PatternRule(
        rule_id="PATTERN-PY-008",
        name="SHA1 hashing",
        pattern=re.compile(r"\bhashlib\.sha1\s*\("),
        severity="medium",
        category="crypto",
        description="SHA1 is considered weak for security purposes",
        remediation="Use SHA-256 or stronger hash functions",
        cwe="CWE-327",
        owasp="A02:2021",
        languages=["python"],
    ),
    PatternRule(
        rule_id="PATTERN-PY-009",
        name="random module for security",
        pattern=re.compile(r"\brandom\.(choice|randint|random|shuffle|sample)\s*\("),
        severity="medium",
        category="crypto",
        description="random module is not cryptographically secure",
        remediation="Use secrets module for security-sensitive random values",
        cwe="CWE-330",
        owasp="A02:2021",
        languages=["python"],
    ),
    PatternRule(
        rule_id="PATTERN-PY-010",
        name="assert used for validation",
        pattern=re.compile(r"^\s*assert\s+.+,?\s*['\"]"),
        severity="low",
        category="misc",
        description="assert statements are removed with -O flag, not suitable for validation",
        remediation="Use explicit if/raise for input validation",
        cwe="CWE-617",
        owasp="A04:2021",
        languages=["python"],
    ),
    PatternRule(
        rule_id="PATTERN-PY-011",
        name="Bare except clause",
        pattern=re.compile(r"\bexcept\s*:"),
        severity="low",
        category="misc",
        description="Bare except catches all exceptions including KeyboardInterrupt",
        remediation="Catch specific exceptions or use 'except Exception:'",
        cwe="CWE-396",
        languages=["python"],
    ),
    PatternRule(
        rule_id="PATTERN-PY-012",
        name="requests without timeout",
        pattern=re.compile(r"requests\.(get|post|put|delete|patch|head|options)\s*\([^)]+\)"),
        severity="medium",
        category="network",
        description="HTTP requests without timeout can hang indefinitely",
        remediation="Always specify a timeout parameter",
        cwe="CWE-400",
        owasp="A05:2021",
        languages=["python"],
    ),
    PatternRule(
        rule_id="PATTERN-PY-013",
        name="verify=False in requests",
        pattern=re.compile(r"requests\.\w+\s*\([^)]*verify\s*=\s*False"),
        severity="high",
        category="crypto",
        description="Disabling SSL verification allows MITM attacks",
        remediation="Always verify SSL certificates. Use verify=True or a custom CA bundle",
        cwe="CWE-295",
        owasp="A02:2021",
        languages=["python"],
    ),
    PatternRule(
        rule_id="PATTERN-PY-014",
        name="Hardcoded localhost binding",
        pattern=re.compile(r"host\s*=\s*['\"]0\.0\.0\.0['\"]"),
        severity="medium",
        category="network",
        description="Binding to 0.0.0.0 exposes the service to all interfaces",
        remediation="Bind to 127.0.0.1 for local-only access or use environment variables",
        cwe="CWE-200",
        owasp="A01:2021",
        languages=["python"],
    ),
    PatternRule(
        rule_id="PATTERN-PY-015",
        name="Debug mode enabled",
        pattern=re.compile(r"(?i)(debug\s*=\s*True|DEBUG\s*=\s*True)"),
        severity="medium",
        category="config",
        description="Debug mode may expose sensitive information",
        remediation="Disable debug mode in production",
        cwe="CWE-215",
        owasp="A05:2021",
        languages=["python"],
    ),
    PatternRule(
        rule_id="PATTERN-PY-016",
        name="SQL string formatting",
        pattern=re.compile(r"(execute|cursor\.execute)\s*\([^)]*(%s|\.format\(|f['\"])"),
        severity="high",
        category="injection",
        description="SQL query with string formatting is vulnerable to SQL injection",
        remediation="Use parameterized queries with placeholders",
        cwe="CWE-89",
        owasp="A03:2021",
        languages=["python"],
    ),
    PatternRule(
        rule_id="PATTERN-PY-017",
        name="tempfile.mktemp() usage",
        pattern=re.compile(r"\btempfile\.mktemp\s*\("),
        severity="medium",
        category="misc",
        description="mktemp is vulnerable to race conditions",
        remediation="Use tempfile.mkstemp() or tempfile.NamedTemporaryFile()",
        cwe="CWE-377",
        owasp="A01:2021",
        languages=["python"],
    ),
    PatternRule(
        rule_id="PATTERN-PY-018",
        name="XML parsing without defusing",
        pattern=re.compile(r"\b(xml\.etree|xml\.dom|xml\.sax)\.\w+\.(parse|fromstring)"),
        severity="high",
        category="injection",
        description="Standard XML parsers are vulnerable to XXE attacks",
        remediation="Use defusedxml library or disable external entities",
        cwe="CWE-611",
        owasp="A05:2021",
        languages=["python"],
    ),
]

# JavaScript/TypeScript dangerous patterns
JS_PATTERNS: list[PatternRule] = [
    PatternRule(
        rule_id="PATTERN-JS-001",
        name="eval() usage",
        pattern=re.compile(r"\beval\s*\("),
        severity="critical",
        category="injection",
        description="eval() can execute arbitrary JavaScript code",
        remediation="Avoid eval(). Use JSON.parse() for JSON or Function constructor for specific cases",
        cwe="CWE-95",
        owasp="A03:2021",
        languages=["javascript", "typescript"],
    ),
    PatternRule(
        rule_id="PATTERN-JS-002",
        name="innerHTML assignment",
        pattern=re.compile(r"\.innerHTML\s*="),
        severity="high",
        category="xss",
        description="innerHTML can lead to XSS if user input is included",
        remediation="Use textContent for text or sanitize HTML with DOMPurify",
        cwe="CWE-79",
        owasp="A03:2021",
        languages=["javascript", "typescript"],
    ),
    PatternRule(
        rule_id="PATTERN-JS-003",
        name="document.write() usage",
        pattern=re.compile(r"\bdocument\.write\s*\("),
        severity="high",
        category="xss",
        description="document.write() can lead to XSS vulnerabilities",
        remediation="Use DOM manipulation methods like createElement() and appendChild()",
        cwe="CWE-79",
        owasp="A03:2021",
        languages=["javascript", "typescript"],
    ),
    PatternRule(
        rule_id="PATTERN-JS-004",
        name="outerHTML assignment",
        pattern=re.compile(r"\.outerHTML\s*="),
        severity="high",
        category="xss",
        description="outerHTML can lead to XSS if user input is included",
        remediation="Use textContent or sanitize HTML content",
        cwe="CWE-79",
        owasp="A03:2021",
        languages=["javascript", "typescript"],
    ),
    PatternRule(
        rule_id="PATTERN-JS-005",
        name="new Function() usage",
        pattern=re.compile(r"\bnew\s+Function\s*\("),
        severity="critical",
        category="injection",
        description="new Function() creates functions from strings, similar to eval()",
        remediation="Avoid dynamic function creation from user input",
        cwe="CWE-95",
        owasp="A03:2021",
        languages=["javascript", "typescript"],
    ),
    PatternRule(
        rule_id="PATTERN-JS-006",
        name="setTimeout/setInterval with string",
        pattern=re.compile(r"(setTimeout|setInterval)\s*\(\s*['\"]"),
        severity="high",
        category="injection",
        description="setTimeout/setInterval with strings acts like eval()",
        remediation="Pass a function reference instead of a string",
        cwe="CWE-95",
        owasp="A03:2021",
        languages=["javascript", "typescript"],
    ),
    PatternRule(
        rule_id="PATTERN-JS-007",
        name="RegExp with user input",
        pattern=re.compile(r"\bnew\s+RegExp\s*\("),
        severity="medium",
        category="injection",
        description="RegExp with user input can cause ReDoS",
        remediation="Escape user input or use safe regex libraries",
        cwe="CWE-1333",
        owasp="A03:2021",
        languages=["javascript", "typescript"],
    ),
    PatternRule(
        rule_id="PATTERN-JS-008",
        name="location.href assignment",
        pattern=re.compile(r"location\.(href|replace)\s*="),
        severity="medium",
        category="redirect",
        description="Open redirect if user input controls the URL",
        remediation="Validate URLs against a whitelist of allowed domains",
        cwe="CWE-601",
        owasp="A01:2021",
        languages=["javascript", "typescript"],
    ),
    PatternRule(
        rule_id="PATTERN-JS-009",
        name="postMessage without origin check",
        pattern=re.compile(r"\.postMessage\s*\([^,]+,\s*['\"]?\*['\"]?\s*\)"),
        severity="high",
        category="misc",
        description="postMessage with '*' allows any origin to receive the message",
        remediation="Specify the exact target origin instead of '*'",
        cwe="CWE-346",
        owasp="A01:2021",
        languages=["javascript", "typescript"],
    ),
    PatternRule(
        rule_id="PATTERN-JS-010",
        name="localStorage sensitive data",
        pattern=re.compile(r"localStorage\.(setItem|getItem)\s*\([^)]*(token|password|secret|key|auth)", re.IGNORECASE),
        severity="medium",
        category="storage",
        description="Storing sensitive data in localStorage is accessible to XSS attacks",
        remediation="Use httpOnly cookies for sensitive data or encrypt before storing",
        cwe="CWE-922",
        owasp="A02:2021",
        languages=["javascript", "typescript"],
    ),
    PatternRule(
        rule_id="PATTERN-JS-011",
        name="console.log with sensitive data",
        pattern=re.compile(r"console\.(log|debug|info)\s*\([^)]*(password|secret|token|key|credential)", re.IGNORECASE),
        severity="low",
        category="logging",
        description="Logging sensitive data may expose credentials",
        remediation="Remove console.log statements with sensitive data in production",
        cwe="CWE-532",
        owasp="A09:2021",
        languages=["javascript", "typescript"],
    ),
    PatternRule(
        rule_id="PATTERN-JS-012",
        name="Dangerously set innerHTML (React)",
        pattern=re.compile(r"dangerouslySetInnerHTML"),
        severity="high",
        category="xss",
        description="dangerouslySetInnerHTML can lead to XSS",
        remediation="Sanitize HTML with DOMPurify before using",
        cwe="CWE-79",
        owasp="A03:2021",
        languages=["javascript", "typescript"],
    ),
    PatternRule(
        rule_id="PATTERN-JS-013",
        name="SQL template string (Node.js)",
        pattern=re.compile(r"(query|execute)\s*\(\s*`[^`]*\$\{"),
        severity="high",
        category="injection",
        description="SQL query with template literals is vulnerable to injection",
        remediation="Use parameterized queries with prepared statements",
        cwe="CWE-89",
        owasp="A03:2021",
        languages=["javascript", "typescript"],
    ),
    PatternRule(
        rule_id="PATTERN-JS-014",
        name="Express CORS wildcard",
        pattern=re.compile(r"cors\s*\(\s*\{[^}]*origin\s*:\s*['\"]?\*['\"]?"),
        severity="medium",
        category="config",
        description="CORS with origin '*' allows any website to make requests",
        remediation="Specify allowed origins explicitly",
        cwe="CWE-346",
        owasp="A01:2021",
        languages=["javascript", "typescript"],
    ),
    PatternRule(
        rule_id="PATTERN-JS-015",
        name="Disabled CSRF protection",
        pattern=re.compile(r"(?i)csrf\s*[=:]\s*(false|disabled|off)"),
        severity="high",
        category="config",
        description="Disabling CSRF protection allows cross-site request forgery",
        remediation="Enable CSRF protection for state-changing operations",
        cwe="CWE-352",
        owasp="A01:2021",
        languages=["javascript", "typescript"],
    ),
]


def scan_file(filepath: str | Path) -> list[dict[str, Any]]:
    """Scan a single file for dangerous patterns."""
    findings: list[dict[str, Any]] = []
    path = Path(filepath)
    
    # Determine language
    ext = path.suffix.lower()
    if ext == ".py":
        patterns = PYTHON_PATTERNS
        language = "python"
    elif ext in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        patterns = JS_PATTERNS
        language = "javascript"
    else:
        return findings  # Unsupported file type
    
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings
    
    lines = content.split("\n")
    
    for line_num, line in enumerate(lines, 1):
        # Skip comments
        stripped = line.strip()
        if language == "python" and stripped.startswith("#"):
            continue
        if language == "javascript" and (stripped.startswith("//") or stripped.startswith("*")):
            continue
        
        for rule in patterns:
            if rule.pattern and rule.pattern.search(line):
                findings.append({
                    "check_id": rule.rule_id,
                    "check_name": rule.name,
                    "path": str(path),
                    "start": {"line": line_num, "col": 0},
                    "end": {"line": line_num, "col": len(line)},
                    "extra": {
                        "message": rule.description,
                        "severity": rule.severity.upper(),
                        "lines": line.strip()[:200],
                        "metadata": {
                            "category": rule.category,
                            "cwe": rule.cwe,
                            "owasp": rule.owasp,
                            "remediation": rule.remediation,
                        },
                    },
                })
    
    return findings


def scan_files(files: list[str]) -> dict[str, Any]:
    """Scan multiple files for dangerous patterns."""
    all_findings: list[dict[str, Any]] = []
    errors: list[str] = []
    
    for filepath in files:
        try:
            findings = scan_file(filepath)
            all_findings.extend(findings)
        except Exception as e:
            errors.append(f"Error scanning {filepath}: {e}")
    
    return {
        "results": all_findings,
        "errors": errors,
        "scanner": "patterns",
        "version": "1.0.0",
        "paths": {"scanned": files},
    }


def run_pattern_scanner(files: list[str]) -> dict[str, Any]:
    """Run the pattern scanner on provided files."""
    return scan_files(files)


# AST-based analysis for Python (more accurate than regex)
class PythonDangerousCallVisitor(ast.NodeVisitor):
    """AST visitor to find dangerous function calls in Python."""
    
    DANGEROUS_CALLS = {
        "eval": ("critical", "CWE-95", "Use ast.literal_eval() for safe evaluation"),
        "exec": ("critical", "CWE-95", "Avoid dynamic code execution"),
        "compile": ("high", "CWE-95", "Avoid compiling code from untrusted sources"),
        "input": ("low", "CWE-20", "Validate and sanitize input"),
        "__import__": ("medium", "CWE-502", "Avoid dynamic imports from user input"),
    }
    
    DANGEROUS_MODULES = {
        "pickle": ["load", "loads", "Unpickler"],
        "marshal": ["load", "loads"],
        "yaml": ["load", "unsafe_load"],
        "subprocess": ["call", "run", "Popen", "check_output", "check_call"],
        "os": ["system", "popen", "spawn", "exec"],
        "commands": ["getoutput", "getstatusoutput"],
    }
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.findings: list[dict[str, Any]] = []
    
    def visit_Call(self, node: ast.Call) -> None:
        # Check for direct dangerous calls
        if isinstance(node.func, ast.Name):
            name = node.func.id
            if name in self.DANGEROUS_CALLS:
                severity, cwe, remediation = self.DANGEROUS_CALLS[name]
                self._add_finding(node, name, severity, cwe, remediation)
        
        # Check for dangerous module.function calls
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                module = node.func.value.id
                method = node.func.attr
                if module in self.DANGEROUS_MODULES:
                    if method in self.DANGEROUS_MODULES[module]:
                        self._add_finding(
                            node,
                            f"{module}.{method}",
                            "high",
                            "CWE-502",
                            f"Avoid {module}.{method}() with untrusted data",
                        )
        
        self.generic_visit(node)
    
    def _add_finding(
        self,
        node: ast.AST,
        name: str,
        severity: str,
        cwe: str,
        remediation: str,
    ) -> None:
        self.findings.append({
            "check_id": f"AST-PY-{name.upper()}",
            "check_name": f"Dangerous call: {name}",
            "path": self.filepath,
            "start": {"line": node.lineno, "col": node.col_offset},
            "end": {"line": getattr(node, "end_lineno", node.lineno), "col": getattr(node, "end_col_offset", 0)},
            "extra": {
                "message": f"Dangerous function call: {name}()",
                "severity": severity.upper(),
                "metadata": {
                    "category": "injection",
                    "cwe": cwe,
                    "remediation": remediation,
                },
            },
        })


def analyze_python_ast(filepath: str) -> list[dict[str, Any]]:
    """Perform AST analysis on a Python file."""
    try:
        source = Path(filepath).read_text(encoding="utf-8")
        tree = ast.parse(source)
        visitor = PythonDangerousCallVisitor(filepath)
        visitor.visit(tree)
        return visitor.findings
    except (SyntaxError, UnicodeDecodeError):
        return []
    except Exception:
        return []


def run_comprehensive_scan(files: list[str]) -> dict[str, Any]:
    """Run both pattern-based and AST-based scanning."""
    # Pattern-based results
    pattern_results = scan_files(files)
    
    # AST-based results for Python files
    ast_findings: list[dict[str, Any]] = []
    for filepath in files:
        if filepath.endswith(".py"):
            ast_findings.extend(analyze_python_ast(filepath))
    
    # Merge results
    all_results = pattern_results["results"] + ast_findings
    
    # Deduplicate by file:line:rule
    seen: set[str] = set()
    unique_results: list[dict[str, Any]] = []
    for result in all_results:
        key = f"{result['path']}:{result['start']['line']}:{result['check_id']}"
        if key not in seen:
            seen.add(key)
            unique_results.append(result)
    
    return {
        "results": unique_results,
        "errors": pattern_results.get("errors", []),
        "scanner": "patterns+ast",
        "version": "1.0.0",
        "paths": {"scanned": files},
    }
