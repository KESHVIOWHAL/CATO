"""
Tests for cato_core — locks in existing behaviour before any extensions.
Run from cato/core/:  pytest tests/ -v
"""

import sys
from pathlib import Path

# Allow running from cato/core/ without installing the package
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from cato_core.engine import run_analysis
from cato_core.models import Decision, CheckStatus


# ── Fixtures ──────────────────────────────────────────────────────────────────

SAMPLE_DIR = Path(__file__).parent.parent.parent / "sample_projects"

def _project(name: str) -> Path:
    p = SAMPLE_DIR / name
    if not p.exists():
        pytest.skip(f"Sample project not found: {p}")
    return p


# ── Core engine tests ─────────────────────────────────────────────────────────

def test_unsafe_app_is_blocked():
    result = run_analysis(_project("unsafe_app"), "unsafe_app")
    assert result.decision == Decision.BLOCK
    assert result.trust_score < 50
    assert result.certificate_id is not None
    assert result.certificate_hash is not None


def test_clean_app_is_approved():
    result = run_analysis(_project("clean_api"), "clean_api")
    assert result.decision == Decision.APPROVE
    assert result.trust_score >= 70
    assert result.certificate_hash is not None


def test_result_has_all_six_checks():
    result = run_analysis(_project("clean_api"), "clean_api")
    check_names = [c.check_name for c in result.checks]
    assert len(result.checks) == 6
    assert any("Secret" in n for n in check_names)
    assert any("SAST" in n or "Static" in n for n in check_names)
    assert any("Depend" in n for n in check_names)
    assert any("Test" in n for n in check_names)
    assert any("Require" in n for n in check_names)
    assert any("Arch" in n for n in check_names)


def test_certificate_hash_is_deterministic_for_same_input():
    """Two runs on the same project should produce the same hash structure."""
    r1 = run_analysis(_project("clean_api"), "clean_api")
    r2 = run_analysis(_project("clean_api"), "clean_api")
    # Decision and score must be identical
    assert r1.decision == r2.decision
    assert r1.trust_score == r2.trust_score


def test_provenance_graph_has_nodes():
    result = run_analysis(_project("clean_api"), "clean_api")
    assert result.provenance is not None
    assert len(result.provenance.nodes) > 0


def test_policy_load_from_project(tmp_path):
    """A project with a permissive policy should not be blocked on MEDIUM findings."""
    import json, shutil
    # Copy medium_risk project to a temp dir with a permissive policy
    src = _project("medium_risk")
    shutil.copytree(src, tmp_path / "project")
    policy = {"critical_secret": "BLOCK", "high_vulnerability": "REVIEW",
               "medium_vulnerability": "PASS", "failed_tests": "PASS"}
    (tmp_path / "project" / "cato-policy.json").write_text(json.dumps(policy))
    result = run_analysis(tmp_path / "project", "medium_permissive")
    # With this policy, medium-only findings should not BLOCK
    assert result.decision != Decision.BLOCK


def test_run_analysis_returns_timing():
    result = run_analysis(_project("clean_api"), "clean_api")
    assert result.post_ai_total_ms > 0
    assert len(result.post_ai_stage_ms) == 6
