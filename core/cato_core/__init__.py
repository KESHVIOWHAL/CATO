"""
cato_core — CATO analysis engine.
Importable by CLI, API, and future IDE extension.
"""
from .models import (
    CheckResult, CheckStatus, Decision, Severity, ScanMode,
    Finding, Recommendation, PolicyResult, AnalysisResult,
    TrustCertificate,
)
from .scanner import (
    run_secret_detection, run_sast, run_dependency_scan, run_functional_tests,
)
from .requirement_checker import run_requirement_check
from .architecture_checker import run_architecture_check
from .decision_engine import make_decision
from .certificate import generate_certificate
from .provenance_graph import build_provenance_graph
from .policy import load_policy
from .engine import run_analysis

__all__ = [
    "run_analysis",
    "run_secret_detection", "run_sast", "run_dependency_scan",
    "run_functional_tests", "run_requirement_check", "run_architecture_check",
    "make_decision", "generate_certificate", "build_provenance_graph",
    "load_policy",
    "CheckResult", "CheckStatus", "Decision", "Severity", "ScanMode",
    "Finding", "Recommendation", "PolicyResult", "AnalysisResult",
    "TrustCertificate",
]
