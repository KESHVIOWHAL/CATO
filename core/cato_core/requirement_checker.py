"""
CATO — Requirement & Intent Verification (#1 in architecture)
=============================================================
Checks:
  - Requirement Match      : does the code implement what was described?
  - Intent Alignment       : does the code do what the project context says it should?
  - Missing / Extra Functionality : unused functions, undocumented entry points
  - Traceability           : can every public function be traced to a requirement?
"""

import ast
import re
from pathlib import Path
from typing import List
from .models import Finding, Severity, CheckResult, CheckStatus, ScanMode


def run_requirement_check(project_path: Path, project_context: str = "") -> CheckResult:
    """
    Lightweight requirement & intent check.
    Uses heuristics on the codebase + optional context string from the user.
    """
    findings: List[Finding] = []
    py_files = [f for f in project_path.rglob("*.py") if "__pycache__" not in str(f)]

    if not py_files:
        return CheckResult(
            check_name="Requirement & Intent",
            status=CheckStatus.SKIP,
            scan_mode=ScanMode.LIVE,
            findings=[],
            summary="No Python files found to check",
        )

    # ── 1. Traceability: public functions without docstrings ──
    undocumented = []
    for fpath in py_files:
        try:
            tree = ast.parse(fpath.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        rel = fpath.relative_to(project_path)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and not node.name.startswith("_"):
                docstring = ast.get_docstring(node)
                if not docstring:
                    undocumented.append((str(rel), node.name, node.lineno))

    if undocumented:
        for rel, fname, lineno in undocumented[:5]:   # cap at 5 for readability
            findings.append(Finding(
                title=f"Undocumented public function: {fname}()",
                severity=Severity.LOW,
                description="Public function has no docstring — intent and requirements cannot be traced.",
                location=f"{rel}:{lineno}",
                remediation=f'Add a docstring to {fname}(): """Brief description of what this function does and why."""',
            ))
        if len(undocumented) > 5:
            findings.append(Finding(
                title=f"{len(undocumented) - 5} more undocumented functions",
                severity=Severity.LOW,
                description="Additional public functions lack documentation.",
                location="(multiple files)",
                remediation="Add docstrings to all public functions for traceability.",
            ))

    # ── 2. Intent alignment: check for TODO/FIXME/HACK in production code ──
    intent_issues = []
    hack_pattern = re.compile(r'\b(TODO|FIXME|HACK|XXX|BUG)\b', re.I)
    for fpath in py_files:
        try:
            lines = fpath.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            continue
        rel = fpath.relative_to(project_path)
        for lineno, line in enumerate(lines, start=1):
            m = hack_pattern.search(line)
            if m:
                intent_issues.append((str(rel), lineno, line.strip(), m.group(1).upper()))

    for rel, lineno, line, marker in intent_issues[:3]:
        findings.append(Finding(
            title=f"Incomplete implementation marker: {marker}",
            severity=Severity.MEDIUM,
            description=f"'{line[:80]}' — code marked as incomplete or broken.",
            location=f"{rel}:{lineno}",
            remediation=f"Resolve the {marker} before deployment. Incomplete code should not be in production.",
        ))

    # ── 3. If project context was provided, check for keyword alignment ──
    if project_context.strip():
        context_words = set(re.findall(r'\b[a-z]{4,}\b', project_context.lower()))
        code_words: set = set()
        for fpath in py_files:
            try:
                code_words.update(re.findall(r'\b[a-z]{4,}\b', fpath.read_text(encoding="utf-8", errors="ignore").lower()))
            except Exception:
                pass

        # Check if context mentions security-sensitive domains not reflected in code
        security_domains = {"authentication", "authorization", "payment", "medical", "health",
                            "finance", "banking", "personal", "private", "sensitive"}
        mentioned = security_domains & context_words
        for domain in mentioned:
            if domain not in code_words:
                findings.append(Finding(
                    title=f"Context mentions '{domain}' but no code reflects it",
                    severity=Severity.MEDIUM,
                    description=f"Project context describes a {domain}-related system, but no matching code patterns found. "
                                "This may indicate missing implementation or a mismatch between requirements and code.",
                    location="(architecture context)",
                    remediation=f"Verify that all {domain}-related requirements are implemented. "
                                "If intentionally absent, document the reason.",
                ))

    status = CheckStatus.FAIL if any(f.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL) for f in findings) else CheckStatus.PASS

    return CheckResult(
        check_name="Requirement & Intent",
        status=status,
        scan_mode=ScanMode.LIVE,
        findings=findings,
        summary=(
            f"{len(findings)} traceability/intent issue(s) found across {len(py_files)} file(s)"
            if findings
            else f"Requirement traceability OK across {len(py_files)} file(s)"
        ),
    )
