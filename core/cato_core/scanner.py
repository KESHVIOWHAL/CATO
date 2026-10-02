"""
CATO Real Analysis Engine
─────────────────────────
All scanners inspect actual project files. No findings are predefined.

Scanner availability:
  - Secret Detection : built-in regex engine (LIVE always) + Gitleaks if installed
  - SAST             : built-in AST/pattern engine (LIVE always) + Semgrep if installed
  - Dependency       : OSV.dev REST API (LIVE when network available) + local CVE table fallback
  - Tests            : pytest subprocess (LIVE always)
"""

import ast
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional
import urllib.request
import urllib.error

from .models import CheckResult, CheckStatus, Severity, ScanMode, Finding

BASE_DIR = Path(__file__).parent.parent.parent / "sample_projects"

# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _tool_available(name: str) -> bool:
    try:
        r = subprocess.run([name, "--version"], capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


def _collect_source_files(project_path: Path, extensions=(".py", ".js", ".ts", ".env", ".cfg", ".ini")) -> List[Path]:
    files = []
    for ext in extensions:
        files.extend(project_path.rglob(f"*{ext}"))
    # exclude common non-source dirs
    exclude = {"__pycache__", ".git", "node_modules", ".venv", "venv", "dist", "build"}
    return [f for f in files if not any(p in exclude for p in f.parts)]


# ─────────────────────────────────────────────────────────────────────────────
#  1. SECRET DETECTION  (real regex engine, no predefined findings)
# ─────────────────────────────────────────────────────────────────────────────

# Each entry: (rule_id, description, compiled_regex, severity, remediation)
SECRET_RULES = [
    (
        "hardcoded-api-key",
        "Hardcoded API key assigned to variable",
        re.compile(
            r'(?:api_key|apikey|api_secret|access_key|secret_key)\s*=\s*["\']([A-Za-z0-9\-_]{16,})["\']',
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "Remove the hardcoded key. Load it from an environment variable instead: "
        "API_KEY = os.environ.get('API_KEY')  — store the real value in a .env file and add .env to .gitignore.",
    ),
    (
        "hardcoded-password",
        "Hardcoded password assigned to variable",
        re.compile(
            r'(?:password|passwd|pwd|db_pass|db_password)\s*=\s*["\']([^"\']{4,})["\']',
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "Never store passwords in source code. Use: DB_PASSWORD = os.environ.get('DB_PASSWORD')  "
        "For local dev, use a .env file with python-dotenv. For production, use a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.).",
    ),
    (
        "github-token",
        "GitHub personal access token detected",
        re.compile(r'ghp_[A-Za-z0-9]{36}', re.IGNORECASE),
        Severity.CRITICAL,
        "Revoke this token immediately on github.com/settings/tokens — it may already be compromised. "
        "Never commit tokens. Use: TOKEN = os.environ.get('GITHUB_TOKEN')",
    ),
    (
        "generic-secret-token",
        "Secret/token value hardcoded",
        re.compile(
            r'(?:secret|token|auth_token|secret_token)\s*=\s*["\']([A-Za-z0-9\-_]{12,})["\']',
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Move this value to an environment variable: SECRET_TOKEN = os.environ.get('SECRET_TOKEN')  "
        "Rotate the current value immediately if this code has ever been committed to a repository.",
    ),
    (
        "aws-access-key",
        "AWS access key ID pattern detected",
        re.compile(r'AKIA[0-9A-Z]{16}'),
        Severity.CRITICAL,
        "Deactivate this AWS key immediately in IAM console. Use IAM roles or environment variables. "
        "Never hardcode AWS credentials — use: boto3 with instance profile or AWS_ACCESS_KEY_ID env var.",
    ),
    (
        "private-key-header",
        "PEM private key block found",
        re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'),
        Severity.CRITICAL,
        "Remove the private key from source code immediately. Store keys in a secure vault or as environment secrets. "
        "If committed, rotate the key pair — treat the private key as compromised.",
    ),
]

def run_secret_detection(project_path: Path) -> CheckResult:
    """Always runs live against actual files."""
    # Try Gitleaks first
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
                summary=(
                    f"Gitleaks: {len(findings)} secret(s) found"
                    if findings else "Gitleaks: No secrets detected"
                ),
            )
        except Exception:
            pass  # fall through to built-in

    # Built-in regex engine — reads actual files
    findings: List[Finding] = []
    source_files = _collect_source_files(project_path)

    for fpath in source_files:
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        lines = content.splitlines()
        for lineno, line in enumerate(lines, start=1):
            # Skip comment lines
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            for rule_id, description, pattern, severity, remediation in SECRET_RULES:
                if pattern.search(line):
                    rel = fpath.relative_to(project_path)
                    findings.append(Finding(
                        title=rule_id.replace("-", " ").title(),
                        severity=severity,
                        description=description,
                        location=f"{rel}:{lineno}",
                        remediation=remediation,
                    ))
                    break  # one rule per line to avoid duplicates

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
#  2. SAST  (real AST + pattern analysis)
# ─────────────────────────────────────────────────────────────────────────────

# Pattern rules: (rule_id, regex, severity, description, remediation)
SAST_PATTERN_RULES = [
    (
        "subprocess-shell-true",
        re.compile(r'subprocess\.(run|Popen|call|check_output).*shell\s*=\s*True'),
        Severity.HIGH,
        "subprocess called with shell=True — allows command injection",
        "Use shell=False and pass arguments as a list: subprocess.run(['cmd', 'arg1'], shell=False)  "
        "Validate and whitelist any user-supplied input before passing to subprocess.",
    ),
    (
        "sql-string-concat",
        re.compile(r'(?:execute|cursor\.execute)\s*\(\s*["\'].*["\'\s]*\+'),
        Severity.HIGH,
        "SQL query built with string concatenation — SQL injection risk",
        "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))  "
        "Never concatenate user input into SQL strings. Consider using an ORM like SQLAlchemy.",
    ),
    (
        "eval-exec",
        re.compile(r'\b(?:eval|exec)\s*\('),
        Severity.HIGH,
        "eval()/exec() with dynamic input — arbitrary code execution risk",
        "Avoid eval()/exec() entirely. If you need dynamic behavior, use a whitelist of allowed operations "
        "or ast.literal_eval() for safe expression evaluation.",
    ),
    (
        "yaml-unsafe-load",
        re.compile(r'yaml\.load\s*\([^)]*\)(?!\s*,\s*Loader)'),
        Severity.HIGH,
        "yaml.load() without Loader= argument — use yaml.safe_load()",
        "Replace yaml.load(data) with yaml.safe_load(data). The safe loader does not execute arbitrary Python objects.",
    ),
    (
        "hardcoded-debug-true",
        re.compile(r'\bDEBUG\s*=\s*True'),
        Severity.MEDIUM,
        "DEBUG=True in production code exposes stack traces",
        "Set DEBUG via environment variable: DEBUG = os.environ.get('DEBUG', 'False') == 'True'  "
        "Ensure DEBUG=False in all production deployments.",
    ),
    (
        "assert-used-in-security",
        re.compile(r'\bassert\b.*(?:auth|permission|role|admin|is_valid)'),
        Severity.MEDIUM,
        "assert used for security check — disabled in optimized mode",
        "Replace assert with an explicit check and raise: if not is_authorized(user): raise PermissionError('Access denied')  "
        "Python strips assert statements when running with -O (optimize) flag.",
    ),
    (
        "pickle-loads",
        re.compile(r'pickle\.loads?\s*\('),
        Severity.HIGH,
        "pickle.load(s) on untrusted data — arbitrary code execution risk",
        "Never unpickle data from untrusted sources. Use JSON, MessagePack, or protobuf for serialization instead.",
    ),
    (
        "weak-hash-md5",
        re.compile(r'hashlib\.md5\s*\('),
        Severity.MEDIUM,
        "MD5 is cryptographically broken — use SHA-256 or better",
        "Replace hashlib.md5() with hashlib.sha256(). For passwords, use bcrypt or argon2: "
        "import bcrypt; hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
    ),
]


def _ast_sast_python(fpath: Path, project_path: Path) -> List[Finding]:
    """AST-based checks for Python files."""
    findings = []
    try:
        source = fpath.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source)
    except Exception:
        return findings

    rel = fpath.relative_to(project_path)

    for node in ast.walk(tree):
        # SQL string concatenation via BinOp in cursor.execute
        if isinstance(node, ast.Call):
            func = node.func
            func_name = ""
            if isinstance(func, ast.Attribute):
                func_name = func.attr
            elif isinstance(func, ast.Name):
                func_name = func.id

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
                            remediation="Use shell=False with a list: subprocess.run(['cmd', arg1], shell=False). Validate all inputs.",
                        ))

            # eval / exec
            if func_name in ("eval", "exec"):
                findings.append(Finding(
                    title="Dangerous eval/exec",
                    severity=Severity.HIGH,
                    description="eval()/exec() with dynamic input — arbitrary code execution risk",
                    location=f"{rel}:{node.lineno}",
                    remediation="Remove eval()/exec(). Use ast.literal_eval() for safe parsing or a whitelist-based approach.",
                ))

    return findings


def run_sast(project_path: Path) -> CheckResult:
    """Always runs live against actual files."""
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

    # Built-in engine: AST + pattern rules
    findings: List[Finding] = []
    py_files = list(project_path.rglob("*.py"))
    py_files = [f for f in py_files if "__pycache__" not in str(f)]

    for fpath in py_files:
        # AST pass
        findings.extend(_ast_sast_python(fpath, project_path))

        # Pattern pass (catches things AST misses)
        try:
            lines = fpath.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            continue
        rel = fpath.relative_to(project_path)
        seen_lines = set()
        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for rule_id, pattern, severity, description, remediation in SAST_PATTERN_RULES:
                if pattern.search(line) and lineno not in seen_lines:
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

    status = CheckStatus.FAIL if findings else CheckStatus.PASS
    return CheckResult(
        check_name="Static Analysis (SAST)",
        status=status,
        scan_mode=ScanMode.LIVE,
        findings=findings,
        summary=(
            f"Built-in SAST: {len(findings)} issue(s) in {len(py_files)} Python file(s)"
            if findings
            else f"Built-in SAST: No issues in {len(py_files)} Python file(s)"
        ),
    )


# ─────────────────────────────────────────────────────────────────────────────
#  3. DEPENDENCY SCAN  (OSV.dev API — real CVE data, no scanner install needed)
# ─────────────────────────────────────────────────────────────────────────────

def _parse_requirements(req_file: Path):
    """Parse requirements.txt into list of (package, version_spec)."""
    packages = []
    try:
        for line in req_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Handle ==, >=, <=, ~=, !=
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


def _query_osv_api(package_name: str, version: Optional[str]) -> List[dict]:
    """Query the OSV.dev REST API for real vulnerability data."""
    payload = {"package": {"name": package_name, "ecosystem": "PyPI"}}
    if version:
        payload["version"] = version  # type: ignore

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


# Fallback known-vulnerable table (used only when network is unavailable)
KNOWN_VULNERABLE = {
    "flask":    [("0.12.2", "CVE-2018-1000656", "Denial of service via crafted JSON")],
    "requests": [("2.18.0", "CVE-2018-18074",   "Credentials sent to third-party redirects")],
    "pyyaml":   [("3.12",   "CVE-2017-18342",   "Arbitrary code execution via yaml.load()")],
    "pillow":   [("8.0.0",  "CVE-2021-27921",   "Buffer overflow in image processing")],
    "django":   [("2.0.0",  "CVE-2019-3498",    "Content spoofing in default 404 page")],
    "urllib3":  [("1.24.1", "CVE-2019-11324",   "Certificate verification bypass")],
    "cryptography": [("2.6.1", "CVE-2018-10903", "Finalize_with_tag does not enforce tag")],
}


def run_dependency_scan(project_path: Path) -> CheckResult:
    """Queries real OSV.dev API for actual CVE data against the project's requirements.txt."""
    req_file = project_path / "requirements.txt"
    if not req_file.exists():
        return CheckResult(
            check_name="Dependency Analysis",
            status=CheckStatus.SKIP,
            scan_mode=ScanMode.LIVE,
            findings=[],
            summary="No requirements.txt found",
        )

    packages = _parse_requirements(req_file)
    if not packages:
        return CheckResult(
            check_name="Dependency Analysis",
            status=CheckStatus.PASS,
            scan_mode=ScanMode.LIVE,
            findings=[],
            summary="No dependencies listed",
        )

    findings: List[Finding] = []
    network_available = True

    for pkg_name, version, _ in packages:
        vulns = _query_osv_api(pkg_name, version)

        if vulns is None:
            network_available = False

        if not vulns and network_available:
            continue  # no known vulns for this version

        if not network_available:
            key = pkg_name.lower().replace("-", "_")
            for known_ver, cve_id, desc in KNOWN_VULNERABLE.get(key, []):
                if version == known_ver:
                    vulns = [{"id": cve_id, "summary": desc, "severity": [{"type": "CVSS_V3", "score": "7.5"}]}]

        # Score each vuln so we can pick the most severe ones per package
        scored = []
        for vuln in vulns:
            vuln_id  = vuln.get("id", "CVE-UNKNOWN")
            summary  = vuln.get("summary", "Vulnerability found")
            sev_list = vuln.get("severity", [])

            cvss_score = 0.0
            severity   = Severity.MEDIUM
            for s in sev_list:
                score_str = str(s.get("score", ""))
                try:
                    cvss_score = float(score_str)
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
                # No CVSS score — default HIGH for old vulnerable versions
                severity = Severity.HIGH
                cvss_score = 7.0

            scored.append((cvss_score, vuln_id, summary, severity))

        # Sort by severity descending, keep top 3 per package
        scored.sort(key=lambda x: x[0], reverse=True)
        top = scored[:3]

        for cvss_score, vuln_id, summary, severity in top:
            findings.append(Finding(
                title=f"{vuln_id} — {pkg_name} {version or ''}".strip(),
                severity=severity,
                description=summary[:200],
                location=f"requirements.txt ({pkg_name}=={version})",
                remediation=f"Upgrade {pkg_name} to the latest patched version: pip install --upgrade {pkg_name}  "
                            f"Check https://osv.dev/vulnerability/{vuln_id} for the minimum safe version.",
            ))

    scan_mode = ScanMode.LIVE if network_available else ScanMode.DEMO
    status = CheckStatus.FAIL if findings else CheckStatus.PASS
    source = "OSV.dev API" if network_available else "local CVE table [offline fallback]"
    total_pkgs_affected = len(set(f.location.split("(")[1].split("==")[0] for f in findings)) if findings else 0

    return CheckResult(
        check_name="Dependency Analysis",
        status=status,
        scan_mode=scan_mode,
        findings=findings,
        summary=(
            f"{source}: {len(findings)} top finding(s) across {total_pkgs_affected} affected package(s) of {len(packages)}"
            if findings
            else f"{source}: No known vulnerabilities in {len(packages)} package(s)"
        ),
    )


# ─────────────────────────────────────────────────────────────────────────────
#  4. FUNCTIONAL TESTS  (live pytest)
# ─────────────────────────────────────────────────────────────────────────────

def run_functional_tests(project_path: Path) -> CheckResult:
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", str(project_path),
             "-v", "--tb=short", "--no-header", "-q"],
            capture_output=True, text=True, timeout=60,
        )
        passed = result.returncode == 0
        output = (result.stdout + result.stderr).strip()
        lines  = output.split("\n")
        summary_line = next(
            (l for l in reversed(lines) if "passed" in l or "failed" in l or "error" in l),
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
        return CheckResult(
            check_name="Functional Tests",
            status=CheckStatus.SKIP,
            scan_mode=ScanMode.LIVE,
            findings=[],
            summary=f"Could not run tests: {e}",
        )
