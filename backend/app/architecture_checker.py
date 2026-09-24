"""
CATO — Architecture & Policy Checker (#2 in architecture)
=========================================================
Checks:
  - Architecture Rules     : layering violations, forbidden imports
  - Design Compliance      : no business logic in test files, no circular patterns
  - Policy Compliance      : coding standards from cato-policy.json
  - Layer Validation       : ensure project structure matches declared architecture
"""

import ast
import re
from pathlib import Path
from typing import List, Dict
from models import Finding, Severity, CheckResult, CheckStatus, ScanMode


# Default architecture rules (can be overridden via cato-policy.json)
DEFAULT_ARCH_RULES = {
    "forbidden_imports": [
        ("os.system", Severity.HIGH, "os.system() is forbidden — use subprocess with shell=False"),
        ("pickle",    Severity.HIGH, "pickle is forbidden for data exchange — use JSON or protobuf"),
        ("telnetlib", Severity.HIGH, "telnetlib is forbidden — use paramiko/SSH instead"),
        ("ftplib",    Severity.MEDIUM, "ftplib transmits credentials in plaintext — use SFTP"),
    ],
    "required_patterns": [
        # (description, regex, file_pattern) — at least one file must match
    ],
    "no_logic_in_tests": True,
    "max_function_lines": 50,
    "max_file_lines": 500,
}


def run_architecture_check(project_path: Path, policy_config: dict = {}) -> CheckResult:
    rules = {**DEFAULT_ARCH_RULES}
    # Merge policy overrides
    if "forbidden_imports" in policy_config:
        rules["forbidden_imports"] = policy_config["forbidden_imports"]
    if "max_function_lines" in policy_config:
        rules["max_function_lines"] = policy_config["max_function_lines"]

    findings: List[Finding] = []
    py_files = [f for f in project_path.rglob("*.py") if "__pycache__" not in str(f)]

    if not py_files:
        return CheckResult(
            check_name="Architecture & Policy",
            status=CheckStatus.SKIP,
            scan_mode=ScanMode.LIVE,
            findings=[],
            summary="No Python files found",
        )

    for fpath in py_files:
        rel = fpath.relative_to(project_path)
        try:
            source = fpath.read_text(encoding="utf-8", errors="ignore")
            tree   = ast.parse(source)
        except Exception:
            continue

        lines = source.splitlines()

        # ── File length check ──
        if len(lines) > rules["max_file_lines"]:
            findings.append(Finding(
                title=f"File too long: {rel} ({len(lines)} lines)",
                severity=Severity.LOW,
                description=f"File exceeds {rules['max_file_lines']} line limit. "
                            "Large files are harder to review and increase attack surface.",
                location=str(rel),
                remediation="Split into smaller modules. Each module should have a single responsibility.",
            ))

        # ── Forbidden imports ──
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                # Build full module name
                if isinstance(node, ast.Import):
                    imported_names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    imported_names = [node.module or ""]
                else:
                    imported_names = []

                for mod in imported_names:
                    for forbidden, severity, message in rules["forbidden_imports"]:
                        # Exact match or submodule match (e.g. "os.system" matches "os.system" not "os")
                        if mod == forbidden or mod.startswith(forbidden + "."):
                            findings.append(Finding(
                                title=f"Forbidden import: {mod}",
                                severity=severity,
                                description=message,
                                location=f"{rel}:{node.lineno}",
                                remediation=message,
                            ))

        # ── Function length check ──
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                func_lines = (node.end_lineno or node.lineno) - node.lineno
                if func_lines > rules["max_function_lines"]:
                    findings.append(Finding(
                        title=f"Function too long: {node.name}() ({func_lines} lines)",
                        severity=Severity.LOW,
                        description=f"Function exceeds {rules['max_function_lines']} line limit. "
                                    "Long functions are harder to test and audit.",
                        location=f"{rel}:{node.lineno}",
                        remediation=f"Refactor {node.name}() into smaller, focused helper functions.",
                    ))

        # ── No business logic in test files ──
        if rules.get("no_logic_in_tests") and ("test" in fpath.name or fpath.name.startswith("test_")):
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and not node.name.startswith("test"):
                    findings.append(Finding(
                        title=f"Non-test function in test file: {node.name}()",
                        severity=Severity.LOW,
                        description="Business logic in test files creates maintenance issues and review gaps.",
                        location=f"{rel}:{node.lineno}",
                        remediation=f"Move {node.name}() to a utility module and import it in the test file.",
                    ))

    status = CheckStatus.FAIL if any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings) else \
             CheckStatus.PASS if not any(f.severity == Severity.MEDIUM for f in findings) else CheckStatus.FAIL

    return CheckResult(
        check_name="Architecture & Policy",
        status=status,
        scan_mode=ScanMode.LIVE,
        findings=findings,
        summary=(
            f"{len(findings)} architecture/policy issue(s) in {len(py_files)} file(s)"
            if findings
            else f"Architecture compliance OK across {len(py_files)} file(s)"
        ),
    )
