"""
cato_core.engine — top-level orchestrator.

Single entry point used by CLI, API, and future integrations:

    result = run_analysis(project_path, project_name, project_context)

Preserves the exact 6-check pipeline from the original prototype.
"""

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .models import AnalysisResult
from .policy import load_policy
from .scanner import (
    _collect_source_files,
    run_secret_detection,
    run_dependency_scan,
    run_sast,
    run_functional_tests,
)
from .requirement_checker import run_requirement_check
from .architecture_checker import run_architecture_check
from .decision_engine import make_decision
from .certificate import generate_certificate
from .provenance_graph import build_provenance_graph


def run_analysis(
    project_path: Path,
    project_name: str,
    project_context: str = "",
) -> AnalysisResult:
    """
    Run the full 6-check CATO pipeline on a local project directory.

    Returns an AnalysisResult with decision, trust score, certificate
    hash, and full provenance graph. Does NOT interact with any database
    or blockchain — callers handle persistence.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    policy_config = load_policy(project_path)
    files_scanned = len(_collect_source_files(project_path))

    stage_times: dict = {}

    def timed(fn, *args):
        t0 = time.perf_counter()
        r = fn(*args)
        stage_times[r.check_name] = round((time.perf_counter() - t0) * 1000, 1)
        return r

    t_start = time.perf_counter()

    req_check    = timed(run_requirement_check,  project_path, project_context)
    arch_check   = timed(run_architecture_check, project_path, policy_config)
    secret_check = timed(run_secret_detection,   project_path)
    dep_check    = timed(run_dependency_scan,    project_path)
    sast_check   = timed(run_sast,               project_path)
    test_check   = timed(run_functional_tests,   project_path)

    total_ms = round((time.perf_counter() - t_start) * 1000, 1)

    all_checks = [req_check, arch_check, secret_check, dep_check, sast_check, test_check]

    decision, risk_level, trust_score, reasons, policy_result, recommendations = make_decision(
        all_checks, policy_config
    )

    provenance_obj = build_provenance_graph(all_checks, req_check, arch_check)
    from .models import ProvenanceGraphModel, ProvenanceNodeModel
    provenance = ProvenanceGraphModel(
        nodes=[ProvenanceNodeModel(**n) for n in provenance_obj.to_dict()["nodes"]],
        traceable=provenance_obj.traceable,
        stages=provenance_obj.stages,
    )

    result = AnalysisResult(
        project_name=project_name,
        project_path=str(project_path),
        timestamp=timestamp,
        checks=all_checks,
        decision=decision,
        risk_level=risk_level,
        trust_score=trust_score,
        decision_reasons=reasons,
        policy=policy_result,
        recommendations=recommendations,
        provenance=provenance,
        files_scanned=files_scanned,
        post_ai_stage_ms=stage_times,
        post_ai_total_ms=total_ms,
    )

    cert = generate_certificate(result)
    result.certificate_id = cert.certificate_id
    result.certificate_hash = cert.certificate_hash

    return result
