"""
CATO — Inline Code Analyzer
Accepts raw pasted code (not a ZIP), writes it to a temp directory,
runs the full 6-scanner pipeline, and returns results with workflow steps.
"""

import ast
import re
import tempfile
import shutil
from pathlib import Path
from typing import Optional

from scanner import (
    run_secret_detection, run_sast, run_dependency_scan,
    run_functional_tests, _collect_source_files,
)
from requirement_checker import run_requirement_check
from architecture_checker import run_architecture_check
from decision_engine import make_decision
from provenance_graph import build_provenance_graph
from models import ProvenanceGraphModel, ProvenanceNodeModel


def analyze_inline(
    code: str,
    language: str = "python",
    filename: str = "pasted_code.py",
    requirements: str = "",
    context_notes: str = "",
    policy_override: Optional[dict] = None,
) -> dict:
    """
    Write pasted code to a temp dir and run the full CATO pipeline.
    Returns structured results with per-step workflow info.
    """
    tmp = Path(tempfile.mkdtemp(prefix="cato_inline_"))
    try:
        # Write the pasted code
        code_file = tmp / filename
        code_file.write_text(code, encoding="utf-8")

        # Write requirements if provided
        if requirements.strip():
            (tmp / "requirements.txt").write_text(requirements.strip())

        # Write policy if provided
        policy_config = policy_override or {
            "critical_secret": "BLOCK",
            "high_vulnerability": "BLOCK",
            "medium_vulnerability": "REVIEW",
            "failed_tests": "REVIEW",
        }

        # ── Run all checks ──
        steps = []

        def step(name: str, icon: str, fn, *args):
            import time
            t0 = time.perf_counter()
            result = fn(*args)
            elapsed = round((time.perf_counter() - t0) * 1000, 1)
            steps.append({
                "name":     name,
                "icon":     icon,
                "status":   result.status.value,
                "summary":  result.summary,
                "findings": len(result.findings),
                "ms":       elapsed,
            })
            return result

        req_check  = step("Requirement & Intent",  "📋", run_requirement_check,  tmp, context_notes)
        arch_check = step("Architecture & Policy", "🏛",  run_architecture_check, tmp, policy_config)
        sec_check  = step("Secret Detection",      "🔑", run_secret_detection,   tmp)
        dep_check  = step("Dependency Analysis",   "📦", run_dependency_scan,    tmp)
        sast_check = step("Static Analysis (SAST)","🔬", run_sast,               tmp)
        test_check = step("Functional Tests",      "🧪", run_functional_tests,   tmp)

        all_checks = [req_check, arch_check, sec_check, dep_check, sast_check, test_check]

        decision, risk_level, trust_score, reasons, policy, recommendations = make_decision(
            all_checks, policy_config
        )

        graph = build_provenance_graph(all_checks, req_check, arch_check)
        prov = ProvenanceGraphModel(
            nodes=[ProvenanceNodeModel(**n.to_dict()) for n in graph.nodes],
            traceable=graph.traceable,
            stages=graph.stages,
        )

        # Collect all findings across checks
        all_findings = []
        for check in all_checks:
            for f in check.findings:
                all_findings.append({
                    "check":       check.check_name,
                    "title":       f.title,
                    "severity":    f.severity.value,
                    "description": f.description,
                    "location":    f.location,
                    "remediation": f.remediation,
                })

        return {
            "decision":        decision.value,
            "risk_level":      risk_level,
            "trust_score":     trust_score,
            "workflow_steps":  steps,
            "all_findings":    all_findings,
            "decision_reasons": reasons,
            "policy_passed":   policy.passed,
            "recommendations": [
                {
                    "priority": r.priority,
                    "category": r.category,
                    "title":    r.title,
                    "what":     r.what,
                    "fix":      r.fix,
                    "severity": r.severity.value,
                    "location": r.location,
                }
                for r in recommendations
            ],
            "provenance": prov.model_dump(),
            "files_scanned": len(list(tmp.rglob("*.py"))),
            "lines_scanned": len(code.splitlines()),
        }

    finally:
        shutil.rmtree(tmp, ignore_errors=True)
