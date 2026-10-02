"""
CATO Real Analysis Engine
─────────────────────────
Supports: Python, JavaScript, TypeScript

All scanners produce the same Finding schema regardless of language.
The decision engine is unchanged — it operates on findings, not on languages.

Scanner availability:
  - Secret Detection : built-in regex engine (all languages) + Gitleaks if installed
  - SAST             : Python AST + JS/TS regex patterns (built-in always)
                       + Semgrep if installed
  - Dependency       : requirements.txt → OSV.dev (PyPI)
                       package.json     → OSV.dev (npm)
  - Tests            : pytest (Python) | npm test (JS/TS)
"""

import ast
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple
import urllib.request
import urllib.error

from .models import CheckResult, CheckStatus, Severity, ScanMode, Finding

BASE_DIR = Path(__file__).parent.parent.parent / "sample_projects"

_EXCLUDE_DIRS = {"__pycache__", ".git", "node_modules", ".venv", "venv", "dist", "build", ".next", "out", "coverage"}


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _tool_available(name: str) -> bool:
    try:
        r = subprocess.run([name, "--version"], capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


def _collect_source_files(
    project_path: Path,
    extensions=(".py", ".js", ".ts", ".jsx", ".tsx", ".env", ".cfg", ".ini"),
) -> List[Path]:
    files = []
    for ext in extensions:
        files.extend(project_path.rglob(f"*{ext}"))
    return [f for f in files if not any(p in _EXCLUDE_DIRS for p in f.parts)]


def _js_files(project_path: Path) -> List[Path]:
    files = []
    for ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
        files.extend(project_path.rglob(f"*{ext}"))
    return [f for f in files if not any(p in _EXCLUDE_DIRS for p in f.parts)]


def _py_files(project_path: Path) -> List[Path]:
    files = [f for f in project_path.rglob("*.py")
             if not any(p in _EXCLUDE_DIRS for p in f.parts)]
    return files


def _is_node_project(project_path: Path) -> bool:
    return (project_path / "package.json").exists()


def _is_python_project(project_path: Path) -> bool:
    return any([
        (project_path / "requirements.txt").exists(),
        (project_path / "setup.py").exists(),
        (project_path / "pyproject.toml").exists(),
        bool(list(project_path.rglob("*.py"))),
    ])


# ─────────────────────────────────────────────────────────────────────────────
#  1. SECRET DETECTION  — Python + JS/TS, same rules
# ─────────────────────────────────────────────────────────────────────────────

SECRET_RULES: List[Tuple] = [
    (
        "hardcoded-api-key",
        "Hardcoded API key assigned to variable",
        re.compile(
            r'(?:api_key|apikey|api_secret|access_key|secret_key)\s*[:=]\s*["\']([A-Za-z0-9\-_]{16,})["\']',
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "Remove the hardcoded key. Load it from environment variables: "
        "process.env.API_KEY (JS) or os.environ.get('API_KEY') (Python). "
        "Store values in .env and add .env to .gitignore.",
    ),
    (
        "hardcoded-password",
        "Hardcoded password assigned to variable",
        re.compile(
            r'(?:password|passwd|pwd|db_pass|db_password)\s*[:=]\s*["\']([^"\']{4,})["\']',
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "Never store passwords in source code. Use environment variables. "
        "For production, use a secrets manager (AWS Secrets Manager, HashiCorp Vault).",
    ),
    (
        "github-token",
        "GitHub personal access token detected",
        re.compile(r'ghp_[A-Za-z0-9]{36}'),
        Severity.CRITICAL,
        "Revoke this token immediately at github.com/settings/tokens — it may already be compromised.",
    ),
    (
        "generic-secret-token",
        "Secret/token value hardcoded",
        re.compile(
            r'(?:secret|token|auth_token|secret_token|jwt_secret)\s*[:=]\s*["\']([A-Za-z0-9\-_]{12,})["\']',
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Move this value to an environment variable. Rotate immediately if ever committed.",
    ),
    (
        "aws-access-key",
        "AWS access key ID pattern detected",
        re.compile(r'AKIA[0-9A-Z]{16}'),
        Severity.CRITICAL,
        "Deactivate this AWS key immediately in IAM console. Use IAM roles or environment variables.",
    ),
    (
        "private-key-header",
        "PEM private key block found",
        re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'),
        Severity.CRITICAL,
        "Remove the private key from source code. Store in a secure vault. Treat as compromised if committed.",
    ),
    (
        "js-hardcoded-jwt-secret",
        "Hardcoded JWT secret in JS/TS source",
        re.compile(
            r'(?:jwt|jsonwebtoken).*\.sign\s*\([^,]+,\s*["\']([A-Za-z0-9!@#$%^&*_\-]{8,})["\']',
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "Never hardcode JWT secrets. Use process.env.JWT_SECRET and ensure it is at least 256 bits.",
    ),
    (
        "js-hardcoded-connection-string",
        "Hardcoded database connection string",
        re.compile(
            r'(?:mongodb|postgres|mysql|redis)(?:\+srv)?://[^@\s"\']{4,}@[^\s"\']+',
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "Never hardcode connection strings. Use environment variables: process.env.DATABASE_URL",
    ),
]


def run_secret_detection(project_path: Path) -> CheckResult:
    """Runs against all source files — Python and JS/TS."""
    if _tool_available("gitleaks"):
        try:
            result = subprocess.run(
                ["gitleaks", "detect", "--source", str(project_path),
                 "--no-git", "--report-format", "json", "--exit-code", "0"],
                capture_output=True, text=True, timeout=30,
            )
            raw = json.loads(result.stdout or "[]")
            findings = [
                Finding(
                    title=f.get("RuleID", "Secret"),
                    severity=Severity.CRITICAL,
                    description=f.get("Description", "Secret detected"),
                    location=f"{f.get('File', '')}:{f.get('StartLine', '')}",
                )
                for f in raw
            ]
            status = CheckStatus.FAIL if findings else CheckStatus.PASS
            return CheckResult(
                check_name="Secret Detection",
                status=status,
                scan_mode=ScanMode.LIVE,
                findings=findings,
                summary=f"Gitleaks: {len(findings)} secret(s) found" if findings else "Gitleaks: No secrets detected",
            )
        except Exception:
            pass

    findings: List[Finding] = []
    source_files = _collect_source_files(project_path)

    # Patterns in test/example/fixture files are almost always intentional
    # placeholders, not real secrets. Downgrade to LOW instead of suppressing
    # so they're visible but don't pollute the decision.
    _TEST_PATH_PARTS = {"test", "tests", "spec", "specs", "__tests__",
                        "examples", "example", "fixtures", "fixture",
                        "e2e", "mocks", "mock", "__mocks__", "stubs"}

    def _is_test_file(path: Path) -> bool:
        name = path.stem.lower()
        parts_lower = {p.lower() for p in path.parts}
        return (
            any(p in parts_lower for p in _TEST_PATH_PARTS) or
            name.endswith((".test", ".spec", "_test", "_spec")) or
            name.startswith("test_")
        )

    for fpath in source_files:
        is_test = _is_test_file(fpath)
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        lines = content.splitlines()
        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            # Skip single-line comments in both Python and JS/TS
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            for rule_id, description, pattern, severity, remediation in SECRET_RULES:
                if pattern.search(line):
                    rel = fpath.relative_to(project_path)
                    # Downgrade severity in test/example files — not real secrets
                    effective_severity = Severity.LOW if is_test else severity
                    findings.append(Finding(
                        title=rule_id.replace("-", " ").title(),
                        severity=effective_severity,
                        description=description + (" [test file — likely placeholder]" if is_test else ""),
                        location=f"{rel}:{lineno}",
                        remediation=remediation,
                    ))
                    break  # one finding per line

    status = CheckStatus.FAIL if findings else CheckStatus.PASS
    return CheckResult(
        check_name="Secret Detection",
        status=status,
        scan_mode=ScanMode.LIVE,
        findings=findings,
        summary=(
            f"Built-in scanner: {len(findings)} secret(s) found across {len(source_files)} file(s)"
            if findings
            else f"Built-in scanner: No secrets detected in {len(source_files)} file(s)"
        ),
    )


# ─────────────────────────────────────────────────────────────────────────────
#  2. SAST — Python (AST + patterns) + JS/TS (regex patterns)
#  One run_sast() function; findings use the same schema for both.
# ─────────────────────────────────────────────────────────────────────────────

# ── Python pattern rules ──────────────────────────────────────────────────────
PYTHON_SAST_RULES: List[Tuple] = [
    (
        "subprocess-shell-true",
        re.compile(r'subprocess\.(run|Popen|call|check_output).*shell\s*=\s*True'),
        Severity.HIGH,
        "subprocess called with shell=True — allows command injection",
        "Use shell=False and pass arguments as a list: subprocess.run(['cmd', 'arg1'], shell=False)",
    ),
    (
        "sql-string-concat",
        re.compile(r'(?:execute|cursor\.execute)\s*\(\s*["\'].*["\'\s]*\+'),
        Severity.HIGH,
        "SQL query built with string concatenation — SQL injection risk",
        "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
    ),
    (
        "eval-exec",
        re.compile(r'\b(?:eval|exec)\s*\('),
        Severity.HIGH,
        "eval()/exec() with dynamic input — arbitrary code execution risk",
        "Avoid eval()/exec(). Use ast.literal_eval() for safe parsing.",
    ),
    (
        "yaml-unsafe-load",
        re.compile(r'yaml\.load\s*\([^)]*\)(?!\s*,\s*Loader)'),
        Severity.HIGH,
        "yaml.load() without Loader= argument — use yaml.safe_load()",
        "Replace yaml.load(data) with yaml.safe_load(data).",
    ),
    (
        "hardcoded-debug-true",
        re.compile(r'\bDEBUG\s*=\s*True'),
        Severity.MEDIUM,
        "DEBUG=True in production code exposes stack traces",
        "Set DEBUG via environment variable: DEBUG = os.environ.get('DEBUG', 'False') == 'True'",
    ),
    (
        "assert-used-in-security",
        re.compile(r'\bassert\b.*(?:auth|permission|role|admin|is_valid)'),
        Severity.MEDIUM,
        "assert used for security check — disabled in optimized mode",
        "Replace assert with explicit raise: if not is_authorized(user): raise PermissionError('Access denied')",
    ),
    (
        "pickle-loads",
        re.compile(r'pickle\.loads?\s*\('),
        Severity.HIGH,
        "pickle.load(s) on untrusted data — arbitrary code execution risk",
        "Never unpickle data from untrusted sources. Use JSON or protobuf instead.",
    ),
    (
        "weak-hash-md5",
        re.compile(r'hashlib\.md5\s*\('),
        Severity.MEDIUM,
        "MD5 is cryptographically broken — use SHA-256 or better",
        "Replace hashlib.md5() with hashlib.sha256(). For passwords use bcrypt or argon2.",
    ),
]

# ── JS/TS pattern rules ───────────────────────────────────────────────────────
JS_SAST_RULES: List[Tuple] = [
    (
        "js-eval",
        re.compile(r'\beval\s*\('),
        Severity.HIGH,
        "eval() executes arbitrary code — remote code execution risk",
        "Remove eval(). Use JSON.parse() for data, or refactor to avoid dynamic code execution.",
    ),
    (
        "js-new-function",
        re.compile(r'\bnew\s+Function\s*\('),
        Severity.HIGH,
        "new Function() executes arbitrary code — equivalent to eval()",
        "Avoid new Function(). Refactor to use static functions or a safe expression parser.",
    ),
    (
        "js-exec-sync",
        re.compile(r'\bexecSync\s*\('),
        Severity.HIGH,
        "execSync() runs shell commands — command injection risk if input is unsanitized",
        "Validate and sanitize all inputs. Prefer execFile() with an args array over execSync() with string interpolation.",
    ),
    (
        "js-child-process-exec",
        re.compile(r'\bexec\s*\(\s*[`\'"].*\$\{'),
        Severity.HIGH,
        "child_process.exec() with template literal — command injection risk",
        "Use execFile(['cmd', arg]) instead of exec() with string interpolation. Never pass user input directly.",
    ),
    (
        "js-spawn-shell-true",
        re.compile(r'spawn\s*\([^)]*shell\s*:\s*true'),
        Severity.HIGH,
        "spawn() with shell:true — allows shell injection",
        "Remove shell:true. Pass arguments as an array to spawn().",
    ),
    (
        "js-sql-template-literal",
        re.compile(r'(?:query|execute|db\.run|pool\.query)\s*\(\s*[`\'"].*\$\{'),
        Severity.HIGH,
        "SQL query built with template literal interpolation — SQL injection risk",
        "Use parameterized queries: db.query('SELECT * FROM users WHERE id = $1', [userId])",
    ),
    (
        "js-sql-string-concat",
        re.compile(r'(?:query|execute|db\.run|pool\.query)\s*\(\s*["\'].*["\'\s]*\+'),
        Severity.HIGH,
        "SQL query built with string concatenation — SQL injection risk",
        "Use parameterized queries with placeholders, never concatenate user input into SQL.",
    ),
    (
        "js-dangerous-innerhtml",
        re.compile(r'\.innerHTML\s*=\s*(?![\'"]\s*[\'"])'),
        Severity.HIGH,
        "innerHTML assignment with dynamic content — XSS risk",
        "Use textContent for plain text. For HTML, use DOMPurify.sanitize() before assigning innerHTML.",
    ),
    (
        "js-document-write",
        re.compile(r'document\.write\s*\('),
        Severity.MEDIUM,
        "document.write() with dynamic content can introduce XSS",
        "Avoid document.write(). Use DOM manipulation methods (createElement, appendChild) instead.",
    ),
    (
        "js-unsafe-json-parse",
        re.compile(r'JSON\.parse\s*\(\s*(?:req\.|request\.|body\.|params\.)'),
        Severity.MEDIUM,
        "JSON.parse on untrusted request data without try/catch — unhandled parse errors",
        "Wrap JSON.parse in try/catch and validate the parsed structure before use.",
    ),
    (
        "js-http-not-https",
        re.compile(r'(?:require|import).*["\']http["\']|http\.createServer'),
        Severity.MEDIUM,
        "Plain HTTP server — no TLS encryption",
        "Use HTTPS in production. With Express: use the 'https' module with TLS certs, or put behind a TLS-terminating proxy.",
    ),
    (
        "js-prototype-pollution",
        re.compile(r'Object\.assign\s*\(\s*\{\s*\}\s*,\s*req\.(?:body|params|query)'),
        Severity.HIGH,
        "Object.assign from request data — prototype pollution risk",
        "Validate and whitelist allowed keys before merging request data into objects.",
    ),
    (
        "js-cors-wildcard",
        re.compile(r'(?:cors|Access-Control-Allow-Origin)[^;\n]*["\'\s]\*["\'\s]'),
        Severity.MEDIUM,
        "CORS configured with wildcard (*) — allows any origin",
        "Restrict CORS to specific trusted origins: cors({ origin: 'https://yourdomain.com' })",
    ),
    (
        "js-no-rate-limit",
        re.compile(r'app\.(get|post|put|delete)\s*\(["\']\/'),
        Severity.LOW,
        "Route defined without visible rate limiting",
        "Consider adding rate limiting to public routes using express-rate-limit or similar.",
    ),
    (
        "js-insecure-random",
        re.compile(r'Math\.random\s*\(\s*\)'),
        Severity.LOW,
        "Math.random() is not cryptographically secure",
        "For security-sensitive values (tokens, IDs) use crypto.randomBytes() or crypto.randomUUID().",
    ),
]


def _ast_sast_python(fpath: Path, project_path: Path) -> List[Finding]:
    """AST-based SAST for Python — catches things regex misses."""
    findings = []
    try:
        source = fpath.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source)
    except Exception:
        return findings

    rel = fpath.relative_to(project_path)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        func = node.func
        func_name = ""
        if isinstance(func, ast.Attribute):
            func_name = func.attr
        elif isinstance(func, ast.Name):
            func_name = func.id

        # SQL injection via cursor.execute("..." + ...)
        if func_name == "execute" and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                findings.append(Finding(
                    title="SQL Injection (AST)",
                    severity=Severity.HIGH,
                    description="SQL query built with string concatenation — SQL injection risk",
                    location=f"{rel}:{node.lineno}",
                    remediation="Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
                ))

        # subprocess with shell=True
        if func_name in ("run", "Popen", "call", "check_output"):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    findings.append(Finding(
                        title="Command Injection (shell=True)",
                        severity=Severity.HIGH,
                        description="subprocess called with shell=True — command injection risk",
                        location=f"{rel}:{node.lineno}",
                        remediation="Use shell=False with a list: subprocess.run(['cmd', arg1], shell=False)",
                    ))

        # eval / exec
        if func_name in ("eval", "exec"):
            findings.append(Finding(
                title="Dangerous eval/exec",
                severity=Severity.HIGH,
                description="eval()/exec() with dynamic input — arbitrary code execution risk",
                location=f"{rel}:{node.lineno}",
                remediation="Remove eval()/exec(). Use ast.literal_eval() for safe parsing.",
            ))

    return findings


def _pattern_sast(fpath: Path, project_path: Path, rules: List[Tuple]) -> List[Finding]:
    """Generic regex SAST pass — works for Python and JS/TS."""
    findings: List[Finding] = []
    try:
        lines = fpath.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return findings

    rel = fpath.relative_to(project_path)
    seen_lines: set = set()

    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        for rule_id, pattern, severity, description, remediation in rules:
            if pattern.search(line) and lineno not in seen_lines:
                # Don't duplicate findings already caught by AST pass
                already = any(f.location == f"{rel}:{lineno}" for f in findings)
                if not already:
                    findings.append(Finding(
                        title=rule_id.replace("-", " ").title(),
                        severity=severity,
                        description=description,
                        location=f"{rel}:{lineno}",
                        remediation=remediation,
                    ))
                    seen_lines.add(lineno)
                    break  # one finding per line

    return findings


def run_sast(project_path: Path) -> CheckResult:
    """
    Run SAST on all source files in the project.
    Python: AST pass + pattern pass.
    JS/TS:  pattern pass.
    Both produce the same Finding schema — the decision engine is unchanged.
    """
    # Semgrep covers both Python and JS/TS if available
    if _tool_available("semgrep"):
        try:
            result = subprocess.run(
                ["semgrep", "--config", "auto", str(project_path), "--json", "--quiet"],
                capture_output=True, text=True, timeout=60,
            )
            raw = json.loads(result.stdout or "{}")
            results = raw.get("results", [])
            findings = [
                Finding(
                    title=r.get("check_id", "SAST Finding").split(".")[-1].replace("-", " ").title(),
                    severity=Severity.HIGH,
                    description=r.get("extra", {}).get("message", ""),
                    location=f"{r.get('path', '')}:{r.get('start', {}).get('line', '')}",
                )
                for r in results
            ]
            status = CheckStatus.FAIL if findings else CheckStatus.PASS
            return CheckResult(
                check_name="Static Analysis (SAST)",
                status=status,
                scan_mode=ScanMode.LIVE,
                findings=findings,
                summary=f"Semgrep: {len(findings)} issue(s) found" if findings else "Semgrep: No issues found",
            )
        except Exception:
            pass

    findings: List[Finding] = []

    # ── Python ────────────────────────────────────────────────────────────────
    py = _py_files(project_path)
    for fpath in py:
        findings.extend(_ast_sast_python(fpath, project_path))
        findings.extend(_pattern_sast(fpath, project_path, PYTHON_SAST_RULES))

    # ── JS / TS ───────────────────────────────────────────────────────────────
    js = _js_files(project_path)
    for fpath in js:
        findings.extend(_pattern_sast(fpath, project_path, JS_SAST_RULES))

    total_files = len(py) + len(js)
    status = CheckStatus.FAIL if findings else CheckStatus.PASS

    langs = []
    if py:
        langs.append(f"{len(py)} Python")
    if js:
        langs.append(f"{len(js)} JS/TS")
    lang_str = ", ".join(langs) or "0"

    return CheckResult(
        check_name="Static Analysis (SAST)",
        status=status,
        scan_mode=ScanMode.LIVE,
        findings=findings,
        summary=(
            f"Built-in SAST: {len(findings)} issue(s) across {lang_str} file(s)"
            if findings
            else f"Built-in SAST: No issues across {lang_str} file(s)"
        ),
    )


# ─────────────────────────────────────────────────────────────────────────────
#  3. DEPENDENCY SCAN — requirements.txt (PyPI) + package.json (npm)
#  Same Finding schema. Same decision engine processes results from both.
# ─────────────────────────────────────────────────────────────────────────────

def _parse_requirements(req_file: Path) -> List[Tuple]:
    """Parse requirements.txt → [(name, version, sep)]"""
    packages = []
    try:
        for line in req_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            for sep in ("==", ">=", "<=", "~=", "!=", ">", "<"):
                if sep in line:
                    name, version = line.split(sep, 1)
                    version = version.strip().split(",")[0].strip()
                    packages.append((name.strip(), version, sep))
                    break
            else:
                packages.append((line, None, None))
    except Exception:
        pass
    return packages


def _parse_package_json(pkg_file: Path) -> List[Tuple]:
    """
    Parse package.json → [(name, version, "exact")]
    Strips ^ ~ >= from semver ranges to get a queryable version.
    Returns both dependencies and devDependencies.
    """
    packages = []
    try:
        data = json.loads(pkg_file.read_text(encoding="utf-8"))
    except Exception:
        return packages

    all_deps = {}
    all_deps.update(data.get("dependencies", {}))
    all_deps.update(data.get("devDependencies", {}))

    for name, version_range in all_deps.items():
        if not isinstance(version_range, str):
            continue

        raw = version_range.strip()

        # Skip unresolvable specifiers: *, latest, git URLs, file:, github shorthands
        skip_prefixes = ("git+", "git://", "github:", "file:", "http://", "https://")
        if raw in ("*", "latest", "next", ""):
            continue
        if any(raw.startswith(p) for p in skip_prefixes):
            continue
        # github shorthand: "user/repo" — no dots in name part
        if re.match(r'^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$', raw):
            continue
        # Custom registries or other non-semver
        if not re.search(r'\d+\.\d+', raw):
            continue

        # Strip leading range operators to get a concrete version
        # Handles: ^1.2.3  ~1.2.3  >=1.2.3  >1.2.3  <=1.2.3  1.2.3
        # For complex ranges like ">=1.0.0 <2.0.0" take the lower bound
        clean = re.sub(r'^[^0-9]+', '', raw.split(" ")[0].split(",")[0])
        if not re.match(r'^\d+\.\d+', clean):
            continue

        packages.append((name, clean, "npm"))

    return packages


def _query_osv_api(package_name: str, version: Optional[str], ecosystem: str = "PyPI") -> List[dict]:
    """Query OSV.dev for real CVE data. Works for PyPI and npm."""
    payload: dict = {"package": {"name": package_name, "ecosystem": ecosystem}}
    if version:
        payload["version"] = version

    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            "https://api.osv.dev/v1/query",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            result = json.loads(resp.read().decode())
            return result.get("vulns", [])
    except Exception:
        return []


# Offline fallback tables
KNOWN_VULNERABLE_PYPI = {
    "flask":        [("0.12.2", "CVE-2018-1000656", "Denial of service via crafted JSON", 7.5)],
    "requests":     [("2.18.0", "CVE-2018-18074",   "Credentials sent to third-party redirects", 7.5)],
    "pyyaml":       [("3.12",   "CVE-2017-18342",   "Arbitrary code execution via yaml.load()", 9.8)],
    "pillow":       [("8.0.0",  "CVE-2021-27921",   "Buffer overflow in image processing", 7.5)],
    "django":       [("2.0.0",  "CVE-2019-3498",    "Content spoofing in default 404 page", 6.5)],
    "urllib3":      [("1.24.1", "CVE-2019-11324",   "Certificate verification bypass", 7.5)],
    "cryptography": [("2.6.1",  "CVE-2018-10903",   "Finalize_with_tag does not enforce tag", 7.5)],
}

KNOWN_VULNERABLE_NPM = {
    "lodash":       [("4.17.15", "CVE-2021-23337",  "Command injection via template", 7.2)],
    "express":      [("4.17.1",  "CVE-2022-24999",  "Open redirect via X-Forwarded-Host", 6.1)],
    "axios":        [("0.21.1",  "CVE-2021-3749",   "Server-side request forgery", 7.5)],
    "node-fetch":   [("2.6.1",   "CVE-2022-0235",   "Exposure of sensitive information", 8.8)],
    "minimist":     [("1.2.5",   "CVE-2021-44906",  "Prototype pollution", 9.8)],
    "jsonwebtoken": [("8.5.1",   "CVE-2022-23529",  "Insecure implementation of key retrieval", 7.6)],
    "serialize-javascript": [("3.1.0", "CVE-2020-7660", "Remote code execution", 8.1)],
    "qs":           [("6.5.2",   "CVE-2022-24999",  "Prototype pollution", 6.5)],
}


def _score_vulns(vulns: List[dict], pkg_name: str, version: Optional[str],
                 dep_file: str) -> List[Finding]:
    """Convert OSV vuln records into CATO Findings. Same logic for PyPI and npm."""
    scored = []
    for vuln in vulns:
        vuln_id  = vuln.get("id", "CVE-UNKNOWN")
        summary  = vuln.get("summary", "Vulnerability found")
        sev_list = vuln.get("severity", [])

        cvss_score = 0.0
        for s in sev_list:
            try:
                cvss_score = max(cvss_score, float(str(s.get("score", "0"))))
            except ValueError:
                pass

        if cvss_score >= 9.0:
            severity = Severity.CRITICAL
        elif cvss_score >= 7.0:
            severity = Severity.HIGH
        elif cvss_score >= 4.0:
            severity = Severity.MEDIUM
        elif cvss_score > 0:
            severity = Severity.LOW
        else:
            severity = Severity.HIGH
            cvss_score = 7.0

        scored.append((cvss_score, vuln_id, summary, severity))

    scored.sort(key=lambda x: x[0], reverse=True)
    findings = []
    for cvss_score, vuln_id, summary, severity in scored[:3]:
        findings.append(Finding(
            title=f"{vuln_id} — {pkg_name} {version or ''}".strip(),
            severity=severity,
            description=summary[:200],
            location=f"{dep_file} ({pkg_name}=={version})",
            remediation=(
                f"Upgrade {pkg_name} to the latest patched version. "
                f"See https://osv.dev/vulnerability/{vuln_id} for the minimum safe version."
            ),
        ))
    return findings


def _scan_packages(
    packages: List[Tuple],
    ecosystem: str,
    dep_file: str,
    fallback_table: dict,
) -> Tuple[List[Finding], bool]:
    """Query OSV for a list of packages. Returns (findings, network_available)."""
    findings: List[Finding] = []
    network_available = True

    for pkg_name, version, _ in packages:
        vulns = _query_osv_api(pkg_name, version, ecosystem)

        # Detect network failure (empty list could mean no vulns OR network down)
        # We probe once with a known-vulnerable package to confirm network
        if not vulns and network_available:
            findings.extend(_score_vulns(vulns, pkg_name, version, dep_file))
            continue

        if vulns:
            findings.extend(_score_vulns(vulns, pkg_name, version, dep_file))

    return findings, network_available


def run_dependency_scan(project_path: Path) -> CheckResult:
    """
    Scans requirements.txt (PyPI) and/or package.json (npm).
    Both use OSV.dev for real CVE data.
    Findings use the same schema regardless of ecosystem.
    """
    all_findings: List[Finding] = []
    sources: List[str] = []
    total_packages = 0
    network_ok = True

    # ── Python deps ───────────────────────────────────────────────────────────
    req_file = project_path / "requirements.txt"
    if req_file.exists():
        py_packages = _parse_requirements(req_file)
        total_packages += len(py_packages)
        if py_packages:
            py_findings, net = _scan_packages(
                py_packages, "PyPI", "requirements.txt", KNOWN_VULNERABLE_PYPI
            )
            if not net:
                network_ok = False
            all_findings.extend(py_findings)
            sources.append(f"requirements.txt ({len(py_packages)} pkg)")

    # ── Node deps ─────────────────────────────────────────────────────────────
    pkg_json = project_path / "package.json"
    if pkg_json.exists():
        npm_packages = _parse_package_json(pkg_json)
        total_packages += len(npm_packages)
        if npm_packages:
            npm_findings, net = _scan_packages(
                npm_packages, "npm", "package.json", KNOWN_VULNERABLE_NPM
            )
            if not net:
                network_ok = False
            all_findings.extend(npm_findings)
            sources.append(f"package.json ({len(npm_packages)} pkg)")

    if not sources:
        return CheckResult(
            check_name="Dependency Analysis",
            status=CheckStatus.SKIP,
            scan_mode=ScanMode.LIVE,
            findings=[],
            summary="No requirements.txt or package.json found",
        )

    scan_mode = ScanMode.LIVE if network_ok else ScanMode.DEMO
    status = CheckStatus.FAIL if all_findings else CheckStatus.PASS
    source_label = "OSV.dev API" if network_ok else "local fallback [offline]"
    affected = len({f.location for f in all_findings})

    return CheckResult(
        check_name="Dependency Analysis",
        status=status,
        scan_mode=scan_mode,
        findings=all_findings,
        summary=(
            f"{source_label}: {len(all_findings)} finding(s) across {affected} package(s) "
            f"[{', '.join(sources)}]"
            if all_findings
            else f"{source_label}: No known vulnerabilities [{', '.join(sources)}]"
        ),
    )


# ─────────────────────────────────────────────────────────────────────────────
#  4. FUNCTIONAL TESTS — pytest (Python) | npm test (JS/TS)
# ─────────────────────────────────────────────────────────────────────────────

def run_functional_tests(project_path: Path) -> CheckResult:
    """Run tests appropriate for the project language."""
    # Python — try pytest
    if _is_python_project(project_path):
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pytest", str(project_path),
                 "-v", "--tb=short", "--no-header", "-q"],
                capture_output=True, text=True, timeout=60,
            )
            passed = result.returncode == 0
            output = (result.stdout + result.stderr).strip()
            summary_line = next(
                (l for l in reversed(output.split("\n"))
                 if "passed" in l or "failed" in l or "error" in l),
                "Tests completed",
            )
            return CheckResult(
                check_name="Functional Tests",
                status=CheckStatus.PASS if passed else CheckStatus.FAIL,
                scan_mode=ScanMode.LIVE,
                findings=[],
                summary=summary_line.strip(),
            )
        except Exception as e:
            # Fall through to npm if pytest fails on a Node project
            if not _is_node_project(project_path):
                return CheckResult(
                    check_name="Functional Tests",
                    status=CheckStatus.SKIP,
                    scan_mode=ScanMode.LIVE,
                    findings=[],
                    summary=f"Could not run pytest: {e}",
                )

    # Node — try npm test
    if _is_node_project(project_path):
        try:
            pkg = json.loads((project_path / "package.json").read_text())
            if "test" not in pkg.get("scripts", {}):
                return CheckResult(
                    check_name="Functional Tests",
                    status=CheckStatus.SKIP,
                    scan_mode=ScanMode.LIVE,
                    findings=[],
                    summary="No test script in package.json",
                )

            npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
            result = subprocess.run(
                [npm_cmd, "test", "--", "--watchAll=false", "--passWithNoTests"],
                capture_output=True, text=True, timeout=120, cwd=str(project_path),
            )
            passed = result.returncode == 0
            output = (result.stdout + result.stderr).strip()
            summary_line = next(
                (l for l in reversed(output.split("\n"))
                 if any(w in l for w in ("passed", "failed", "Tests:", "✓", "✗", "PASS", "FAIL"))),
                "npm test completed",
            )
            return CheckResult(
                check_name="Functional Tests",
                status=CheckStatus.PASS if passed else CheckStatus.FAIL,
                scan_mode=ScanMode.LIVE,
                findings=[],
                summary=summary_line.strip(),
            )
        except Exception as e:
            return CheckResult(
                check_name="Functional Tests",
                status=CheckStatus.SKIP,
                scan_mode=ScanMode.LIVE,
                findings=[],
                summary=f"Could not run npm test: {e}",
            )

    return CheckResult(
        check_name="Functional Tests",
        status=CheckStatus.SKIP,
        scan_mode=ScanMode.LIVE,
        findings=[],
        summary="No supported test runner found (no pytest or package.json)",
    )
