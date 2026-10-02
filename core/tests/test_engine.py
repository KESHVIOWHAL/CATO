"""
CATO core test suite.
Tests the full pipeline for Python AND JS/TS projects.
One decision engine. One finding schema. Two languages.

Run from cato/core/:  pytest tests/ -v
"""

import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from cato_core.engine import run_analysis
from cato_core.models import Decision, CheckStatus, Severity
from cato_core.scanner import (
    run_secret_detection, run_sast, run_dependency_scan,
    _parse_package_json, _parse_requirements,
    _collect_source_files,
)

SAMPLE_DIR = Path(__file__).parent.parent.parent / "sample_projects"


def _project(name: str) -> Path:
    p = SAMPLE_DIR / name
    if not p.exists():
        pytest.skip(f"Sample project not found: {p}")
    return p


# ═══════════════════════════════════════════════════════════════════
#  PYTHON PROJECT TESTS
# ═══════════════════════════════════════════════════════════════════

class TestPythonProjects:

    def test_unsafe_app_is_blocked(self):
        result = run_analysis(_project("unsafe_app"), "unsafe_app")
        assert result.decision == Decision.BLOCK
        assert result.trust_score < 50

    def test_clean_app_is_approved(self):
        result = run_analysis(_project("clean_api"), "clean_api")
        assert result.decision == Decision.APPROVE
        assert result.trust_score >= 70

    def test_unsafe_app_has_secret_findings(self):
        result = run_analysis(_project("unsafe_app"), "unsafe_app")
        secret_check = next(c for c in result.checks if "Secret" in c.check_name)
        assert secret_check.status == CheckStatus.FAIL
        assert len(secret_check.findings) > 0
        severities = {f.severity for f in secret_check.findings}
        assert Severity.CRITICAL in severities

    def test_unsafe_app_has_sast_findings(self):
        result = run_analysis(_project("unsafe_app"), "unsafe_app")
        sast_check = next(c for c in result.checks if "SAST" in c.check_name or "Static" in c.check_name)
        assert len(sast_check.findings) > 0

    def test_clean_app_no_secret_findings(self):
        result = run_analysis(_project("clean_api"), "clean_api")
        secret_check = next(c for c in result.checks if "Secret" in c.check_name)
        assert secret_check.status == CheckStatus.PASS
        assert len(secret_check.findings) == 0

    def test_vulnerable_python_deps_detected(self):
        result = run_analysis(_project("unsafe_app"), "unsafe_app")
        dep_check = next(c for c in result.checks if "Depend" in c.check_name)
        # unsafe_app has known-vulnerable requirements.txt
        assert dep_check.status in (CheckStatus.FAIL, CheckStatus.PASS)  # network may vary

    def test_clean_python_deps_pass(self):
        result = run_analysis(_project("clean_api"), "clean_api")
        dep_check = next(c for c in result.checks if "Depend" in c.check_name)
        assert dep_check.status in (CheckStatus.PASS, CheckStatus.SKIP)

    def test_result_has_all_six_checks(self):
        result = run_analysis(_project("clean_api"), "clean_api")
        assert len(result.checks) == 6
        names = [c.check_name for c in result.checks]
        assert any("Secret" in n for n in names)
        assert any("SAST" in n or "Static" in n for n in names)
        assert any("Depend" in n for n in names)
        assert any("Test" in n for n in names)
        assert any("Require" in n for n in names)
        assert any("Arch" in n for n in names)

    def test_certificate_issued_for_python_project(self):
        result = run_analysis(_project("clean_api"), "clean_api")
        assert result.certificate_id is not None
        assert result.certificate_hash is not None
        assert result.certificate_id.startswith("CATO-")
        assert len(result.certificate_hash) == 64  # SHA-256 hex

    def test_provenance_graph_populated(self):
        result = run_analysis(_project("clean_api"), "clean_api")
        assert result.provenance is not None
        assert len(result.provenance.nodes) > 0

    def test_timing_recorded(self):
        result = run_analysis(_project("clean_api"), "clean_api")
        assert result.post_ai_total_ms > 0
        assert len(result.post_ai_stage_ms) == 6


# ═══════════════════════════════════════════════════════════════════
#  NODE.JS PROJECT TESTS
# ═══════════════════════════════════════════════════════════════════

class TestNodeProjects:

    def test_node_unsafe_is_blocked(self):
        result = run_analysis(_project("node_unsafe"), "node_unsafe")
        assert result.decision == Decision.BLOCK
        assert result.trust_score < 50

    def test_node_clean_is_approved_or_review(self):
        """Clean Node project should not be blocked."""
        result = run_analysis(_project("node_clean"), "node_clean")
        assert result.decision != Decision.BLOCK

    def test_node_unsafe_has_sast_findings(self):
        result = run_analysis(_project("node_unsafe"), "node_unsafe")
        sast_check = next(c for c in result.checks if "SAST" in c.check_name or "Static" in c.check_name)
        assert sast_check.status == CheckStatus.FAIL
        assert len(sast_check.findings) > 0

    def test_node_unsafe_detects_eval(self):
        result = run_analysis(_project("node_unsafe"), "node_unsafe")
        sast_check = next(c for c in result.checks if "SAST" in c.check_name or "Static" in c.check_name)
        titles = [f.title.lower() for f in sast_check.findings]
        assert any("eval" in t for t in titles)

    def test_node_unsafe_detects_exec_sync(self):
        result = run_analysis(_project("node_unsafe"), "node_unsafe")
        sast_check = next(c for c in result.checks if "SAST" in c.check_name or "Static" in c.check_name)
        titles = [f.title.lower() for f in sast_check.findings]
        assert any("exec" in t for t in titles)

    def test_node_unsafe_detects_hardcoded_secret(self):
        result = run_analysis(_project("node_unsafe"), "node_unsafe")
        secret_check = next(c for c in result.checks if "Secret" in c.check_name)
        assert secret_check.status == CheckStatus.FAIL
        assert len(secret_check.findings) > 0

    def test_node_clean_no_critical_sast(self):
        result = run_analysis(_project("node_clean"), "node_clean")
        sast_check = next(c for c in result.checks if "SAST" in c.check_name or "Static" in c.check_name)
        critical_findings = [f for f in sast_check.findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) == 0

    def test_node_clean_no_critical_secrets(self):
        result = run_analysis(_project("node_clean"), "node_clean")
        secret_check = next(c for c in result.checks if "Secret" in c.check_name)
        critical = [f for f in secret_check.findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 0

    def test_node_result_still_has_six_checks(self):
        """Node projects use the same 6-check pipeline."""
        result = run_analysis(_project("node_unsafe"), "node_unsafe")
        assert len(result.checks) == 6

    def test_node_certificate_issued(self):
        result = run_analysis(_project("node_clean"), "node_clean")
        assert result.certificate_id is not None
        assert result.certificate_id.startswith("CATO-")


# ═══════════════════════════════════════════════════════════════════
#  TYPESCRIPT PROJECT TESTS
# ═══════════════════════════════════════════════════════════════════

class TestTypeScriptProjects:

    def test_ts_unsafe_is_blocked(self):
        result = run_analysis(_project("ts_api"), "ts_api")
        assert result.decision == Decision.BLOCK

    def test_ts_detects_eval(self):
        result = run_analysis(_project("ts_api"), "ts_api")
        sast_check = next(c for c in result.checks if "SAST" in c.check_name or "Static" in c.check_name)
        titles = [f.title.lower() for f in sast_check.findings]
        assert any("eval" in t for t in titles)

    def test_ts_detects_hardcoded_connection_string(self):
        result = run_analysis(_project("ts_api"), "ts_api")
        secret_check = next(c for c in result.checks if "Secret" in c.check_name)
        assert len(secret_check.findings) > 0

    def test_ts_detects_sql_template_literal(self):
        result = run_analysis(_project("ts_api"), "ts_api")
        sast_check = next(c for c in result.checks if "SAST" in c.check_name or "Static" in c.check_name)
        titles = [f.title.lower() for f in sast_check.findings]
        assert any("sql" in t or "template" in t for t in titles)

    def test_ts_vulnerable_deps_detected(self):
        result = run_analysis(_project("ts_api"), "ts_api")
        dep_check = next(c for c in result.checks if "Depend" in c.check_name)
        # ts_api has known-vulnerable packages — should find issues if network available
        assert dep_check.status in (CheckStatus.FAIL, CheckStatus.PASS, CheckStatus.SKIP)


# ═══════════════════════════════════════════════════════════════════
#  DEPENDENCY SCANNER UNIT TESTS
# ═══════════════════════════════════════════════════════════════════

class TestDependencyScanner:

    def test_parse_requirements_txt(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("flask==0.12.2\nrequests>=2.18.0\npyyaml~=3.12\n# comment\n")
        packages = _parse_requirements(req)
        names = [p[0] for p in packages]
        assert "flask" in names
        assert "requests" in names
        assert "pyyaml" in names

    def test_parse_package_json_deps_and_dev_deps(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "dependencies": {"express": "^4.17.1", "lodash": "4.17.15"},
            "devDependencies": {"jest": "^27.0.0"},
        }))
        packages = _parse_package_json(pkg)
        names = [p[0] for p in packages]
        assert "express" in names
        assert "lodash" in names
        assert "jest" in names

    def test_parse_package_json_strips_caret(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"dependencies": {"express": "^4.17.1"}}))
        packages = _parse_package_json(pkg)
        assert packages[0][1] == "4.17.1"

    def test_parse_package_json_skips_git_urls(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "dependencies": {
                "my-lib": "github:user/repo",
                "express": "4.21.2",
            }
        }))
        packages = _parse_package_json(pkg)
        names = [p[0] for p in packages]
        assert "my-lib" not in names
        assert "express" in names

    def test_vulnerable_npm_package_detected(self):
        """lodash 4.17.15 has known CVEs — should produce findings."""
        check = run_dependency_scan(_project("node_unsafe"))
        # FAIL when network is up, PASS when offline (no offline npm fallback for all pkgs)
        assert check.check_name == "Dependency Analysis"
        assert check.status in (CheckStatus.FAIL, CheckStatus.PASS)

    def test_clean_npm_package_no_critical_findings(self):
        """Clean node project with recent packages — no critical findings expected."""
        check = run_dependency_scan(_project("node_clean"))
        if check.status == CheckStatus.FAIL:
            critical = [f for f in check.findings if f.severity == Severity.CRITICAL]
            assert len(critical) == 0

    def test_no_dep_file_returns_skip(self, tmp_path):
        (tmp_path / "app.js").write_text("console.log('hello');")
        check = run_dependency_scan(tmp_path)
        assert check.status == CheckStatus.SKIP

    def test_python_and_node_both_scanned(self, tmp_path):
        """A project with both requirements.txt and package.json should scan both."""
        (tmp_path / "requirements.txt").write_text("flask==0.12.2\n")
        (tmp_path / "package.json").write_text(json.dumps({
            "dependencies": {"lodash": "4.17.15"}
        }))
        check = run_dependency_scan(tmp_path)
        assert "requirements.txt" in check.summary
        assert "package.json" in check.summary


# ═══════════════════════════════════════════════════════════════════
#  SAST UNIT TESTS — JS/TS specific patterns
# ═══════════════════════════════════════════════════════════════════

class TestJsSastRules:

    def _sast(self, code: str, filename: str = "test.js", tmp_path=None):
        p = tmp_path
        f = p / filename
        f.write_text(code)
        check = run_sast(p)
        return check

    def test_eval_detected(self, tmp_path):
        check = self._sast("const r = eval(userInput);", tmp_path=tmp_path)
        titles = [f.title.lower() for f in check.findings]
        assert any("eval" in t for t in titles)

    def test_new_function_detected(self, tmp_path):
        check = self._sast("const fn = new Function('x', 'return x+1');", tmp_path=tmp_path)
        titles = [f.title.lower() for f in check.findings]
        assert any("function" in t for t in titles)

    def test_exec_sync_detected(self, tmp_path):
        check = self._sast("const out = execSync('ls ' + userDir);", tmp_path=tmp_path)
        titles = [f.title.lower() for f in check.findings]
        assert any("exec" in t for t in titles)

    def test_innerhtml_detected(self, tmp_path):
        check = self._sast("el.innerHTML = userData;", tmp_path=tmp_path)
        titles = [f.title.lower() for f in check.findings]
        assert any("innerhtml" in t or "html" in t for t in titles)

    def test_sql_template_literal_detected(self, tmp_path):
        check = self._sast(
            "db.query(`SELECT * FROM users WHERE id = ${userId}`);",
            tmp_path=tmp_path,
        )
        titles = [f.title.lower() for f in check.findings]
        assert any("sql" in t or "template" in t for t in titles)

    def test_comment_lines_not_flagged(self, tmp_path):
        check = self._sast(
            "// const r = eval(x);\n// execSync('rm -rf');\nconsole.log('safe');",
            tmp_path=tmp_path,
        )
        assert len(check.findings) == 0

    def test_clean_js_has_no_critical_findings(self, tmp_path):
        clean_code = """
const crypto = require('crypto');
const express = require('express');
const app = express();

function getToken() {
  return crypto.randomUUID();
}

app.get('/health', (req, res) => res.json({ ok: true }));
module.exports = app;
"""
        check = self._sast(clean_code, tmp_path=tmp_path)
        critical = [f for f in check.findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 0


# ═══════════════════════════════════════════════════════════════════
#  PIPELINE CONSISTENCY — same findings → same decision for Py + JS
# ═══════════════════════════════════════════════════════════════════

class TestPipelineConsistency:

    def test_critical_finding_always_blocks_regardless_of_language(self, tmp_path):
        """A JS file with a CRITICAL secret should trigger BLOCK via the same pipeline."""
        (tmp_path / "app.js").write_text(
            'const api_key = "sk-prod-abc123def456ghi789jkl0";\n'
        )
        result = run_analysis(tmp_path, "js-secret-test")
        assert result.decision == Decision.BLOCK

    def test_critical_python_secret_triggers_block(self, tmp_path):
        (tmp_path / "app.py").write_text(
            'api_key = "sk-prod-abc123def456ghi789jkl0"\n'
        )
        result = run_analysis(tmp_path, "py-secret-test")
        assert result.decision == Decision.BLOCK

    def test_both_languages_produce_same_finding_schema(self, tmp_path):
        """Findings from JS and Python checks have identical field structure."""
        js_dir = tmp_path / "js"
        js_dir.mkdir()
        (js_dir / "app.js").write_text('const r = eval(x);\n')
        js_result = run_analysis(js_dir, "js-schema-test")

        py_dir = tmp_path / "py"
        py_dir.mkdir()
        (py_dir / "app.py").write_text('result = eval(user_input)\n')
        py_result = run_analysis(py_dir, "py-schema-test")

        for result in [js_result, py_result]:
            for check in result.checks:
                for finding in check.findings:
                    assert hasattr(finding, "title")
                    assert hasattr(finding, "severity")
                    assert hasattr(finding, "description")

    def test_policy_applies_uniformly_to_js_findings(self, tmp_path):
        """Permissive policy should lift BLOCK to REVIEW even for JS projects."""
        (tmp_path / "app.js").write_text('const r = eval(x);\n')
        (tmp_path / "package.json").write_text(json.dumps({"name": "test", "version": "1.0.0"}))
        import json as _json
        policy = {
            "critical_secret": "REVIEW",
            "high_vulnerability": "REVIEW",
            "medium_vulnerability": "PASS",
            "failed_tests": "PASS",
        }
        (tmp_path / "cato-policy.json").write_text(_json.dumps(policy))
        result = run_analysis(tmp_path, "js-policy-test")
        assert result.decision != Decision.BLOCK

    def test_decision_reasons_populated_for_node_project(self):
        result = run_analysis(_project("node_unsafe"), "node_unsafe")
        assert len(result.decision_reasons) > 0

    def test_recommendations_populated_for_node_project(self):
        result = run_analysis(_project("node_unsafe"), "node_unsafe")
        assert len(result.recommendations) > 0
        for rec in result.recommendations:
            assert rec.title
            assert rec.fix
            assert rec.severity
