"""
CATO Real-World Repository Tests
─────────────────────────────────
Clones real public repositories into isolated temp directories.
Runs ONLY static analysis and dependency scanning — no test execution,
no npm install, no arbitrary code from the repository is run.

Repositories tested:
  1. expressjs/express      — mature JS project, conventional package.json
  2. fastify/fastify         — JS, different plugin architecture
  3. nestjs/nest             — large TypeScript monorepo
  4. sindresorhus/got        — smaller TS/JS HTTP library
  5. node_unsafe (local)     — controlled vulnerable fixture (no clone needed)

Validates:
  - Project type detection
  - package.json parsing (including edge case version ranges)
  - npm OSV dependency advisories → normalized Finding schema
  - JS/TS SAST rules fire correctly
  - False positives are manageable (no critical false positives on mature projects)
  - Decision engine produces expected output
  - Certificate generation still works
  - CLI --json output is valid JSON
  - Timing is recorded
  - Controlled vulnerability injection → BLOCK with evidence chain

Run:
    pytest tests/test_real_world.py -v -s --timeout=300

Requires:
    pip install pytest-timeout
"""

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from cato_core.engine import run_analysis
from cato_core.models import Decision, CheckStatus, Severity
from cato_core.scanner import (
    run_secret_detection, run_sast, run_dependency_scan,
    _parse_package_json, _is_node_project, _is_python_project,
)

SAMPLE_DIR = Path(__file__).parent.parent.parent / "sample_projects"
REPOS_DIR = Path(__file__).parent / "_real_repos"   # temp clone target


# ─────────────────────────────────────────────────────────────────────────────
#  Fixtures & helpers
# ─────────────────────────────────────────────────────────────────────────────

def _clone(url: str, name: str, depth: int = 1) -> Optional[Path]:
    """Shallow-clone a repo into REPOS_DIR/<name>. Returns path or None on failure."""
    dest = REPOS_DIR / name
    if dest.exists():
        return dest   # reuse if already cloned
    REPOS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", str(depth), "--quiet", url, str(dest)],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            print(f"\n[clone error] {name}: {result.stderr[:200]}")
            return None
        return dest
    except Exception as e:
        print(f"\n[clone exception] {name}: {e}")
        return None


def _scan_static_only(project_path: Path, name: str) -> dict:
    """
    Run only secret detection, SAST, and dependency scan.
    Does NOT run tests — no repo code is executed.
    Returns a result dict for the summary table.
    """
    t0 = time.perf_counter()

    secret_check = run_secret_detection(project_path)
    sast_check   = run_sast(project_path)
    dep_check    = run_dependency_scan(project_path)

    elapsed_ms = round((time.perf_counter() - t0) * 1000)

    is_node   = _is_node_project(project_path)
    is_python = _is_python_project(project_path)
    lang = "TS" if any(project_path.rglob("*.ts")) else "JS" if is_node else "Python"

    pkg_count = 0
    if (project_path / "package.json").exists():
        from cato_core.scanner import _parse_package_json
        pkg_count += len(_parse_package_json(project_path / "package.json"))
    if (project_path / "requirements.txt").exists():
        from cato_core.scanner import _parse_requirements
        pkg_count += len(_parse_requirements(project_path / "requirements.txt"))

    all_findings = secret_check.findings + sast_check.findings + dep_check.findings
    critical_n = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
    high_n     = sum(1 for f in all_findings if f.severity == Severity.HIGH)

    return {
        "name":        name,
        "lang":        lang,
        "is_node":     is_node,
        "pkg_count":   pkg_count,
        "dep_status":  dep_check.status.value,
        "dep_findings": len(dep_check.findings),
        "sast_status": sast_check.status.value,
        "sast_findings": len(sast_check.findings),
        "secret_status": secret_check.status.value,
        "secret_findings": len(secret_check.findings),
        "critical_n":  critical_n,
        "high_n":      high_n,
        "elapsed_ms":  elapsed_ms,
        "secret_check": secret_check,
        "sast_check":   sast_check,
        "dep_check":    dep_check,
    }


def _print_table(rows: list[dict]):
    """Print the results summary table."""
    header = f"\n{'Repo':<25} {'Lang':<6} {'Pkgs':<6} {'Deps':<8} {'SAST':<6} {'Secrets':<9} {'Critical':<9} {'High':<6} {'ms':<7}"
    print("\n" + "=" * 80)
    print("CATO Real-World Scan Results")
    print("=" * 80)
    print(header)
    print("-" * 80)
    for r in rows:
        dep_s    = f"{r['dep_status']}({r['dep_findings']})"
        sast_s   = f"{r['sast_status']}({r['sast_findings']})"
        secret_s = f"{r['secret_status']}({r['secret_findings']})"
        print(
            f"{r['name']:<25} {r['lang']:<6} {r['pkg_count']:<6} "
            f"{dep_s:<8} {sast_s:<6} {secret_s:<9} "
            f"{r['critical_n']:<9} {r['high_n']:<6} {r['elapsed_ms']:<7}"
        )
    print("=" * 80)


# ─────────────────────────────────────────────────────────────────────────────
#  1. Express — mature JS project
# ─────────────────────────────────────────────────────────────────────────────

class TestExpress:

    @pytest.fixture(scope="class")
    def repo(self):
        path = _clone("https://github.com/expressjs/express.git", "express")
        if not path:
            pytest.skip("Could not clone express")
        return path

    def test_detected_as_node_project(self, repo):
        assert _is_node_project(repo)

    def test_package_json_parsed(self, repo):
        pkgs = _parse_package_json(repo / "package.json")
        assert len(pkgs) > 0
        names = [p[0] for p in pkgs]
        assert any("express" in n or "mocha" in n or "body-parser" in n for n in names)

    def test_no_critical_sast_false_positives(self, repo):
        """Mature framework should have no CRITICAL SAST findings."""
        check = run_sast(repo)
        critical = [f for f in check.findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 0, f"Unexpected critical SAST in express: {[f.title for f in critical]}"

    def test_no_critical_secret_false_positives(self, repo):
        check = run_secret_detection(repo)
        # examples/ files contain intentional demo passwords — should be downgraded to LOW
        critical = [f for f in check.findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 0, \
            f"False positive CRITICAL secrets in express: {[f.title + ' @ ' + str(f.location) for f in critical]}"

    def test_dep_scan_completes_and_normalizes(self, repo):
        check = run_dependency_scan(repo)
        assert check.check_name == "Dependency Analysis"
        assert check.status in (CheckStatus.PASS, CheckStatus.FAIL, CheckStatus.SKIP)
        for f in check.findings:
            assert f.severity in list(Severity)
            assert f.title
            assert f.location

    def test_scan_completes_under_30s(self, repo):
        t0 = time.perf_counter()
        run_sast(repo)
        run_secret_detection(repo)
        elapsed = time.perf_counter() - t0
        assert elapsed < 30, f"Static scan took {elapsed:.1f}s — too slow"


# ─────────────────────────────────────────────────────────────────────────────
#  2. Fastify — JS, different plugin architecture
# ─────────────────────────────────────────────────────────────────────────────

class TestFastify:

    @pytest.fixture(scope="class")
    def repo(self):
        path = _clone("https://github.com/fastify/fastify.git", "fastify")
        if not path:
            pytest.skip("Could not clone fastify")
        return path

    def test_detected_as_node_project(self, repo):
        assert _is_node_project(repo)

    def test_package_json_parsed(self, repo):
        pkgs = _parse_package_json(repo / "package.json")
        assert len(pkgs) > 0

    def test_no_critical_false_positives(self, repo):
        sast_check   = run_sast(repo)
        secret_check = run_secret_detection(repo)
        all_critical = [
            f for f in sast_check.findings + secret_check.findings
            if f.severity == Severity.CRITICAL
        ]
        assert len(all_critical) == 0, \
            f"False positive criticals in fastify: {[f.title + ' @ ' + str(f.location) for f in all_critical]}"

    def test_findings_have_valid_schema(self, repo):
        check = run_sast(repo)
        for f in check.findings:
            assert isinstance(f.title, str) and f.title
            assert f.severity in list(Severity)
            assert isinstance(f.description, str)


# ─────────────────────────────────────────────────────────────────────────────
#  3. NestJS — large TypeScript monorepo
# ─────────────────────────────────────────────────────────────────────────────

class TestNestJS:

    @pytest.fixture(scope="class")
    def repo(self):
        path = _clone("https://github.com/nestjs/nest.git", "nestjs")
        if not path:
            pytest.skip("Could not clone nestjs")
        return path

    def test_detected_as_typescript(self, repo):
        ts_files = list(repo.rglob("*.ts"))
        # exclude node_modules
        ts_files = [f for f in ts_files if "node_modules" not in str(f)]
        assert len(ts_files) > 0

    def test_package_json_parsed(self, repo):
        pkgs = _parse_package_json(repo / "package.json")
        assert len(pkgs) > 0

    def test_sast_handles_large_ts_codebase(self, repo):
        """SAST should complete without crashing on a large TS monorepo."""
        check = run_sast(repo)
        assert check.check_name == "Static Analysis (SAST)"
        assert check.status in list(CheckStatus)

    def test_no_critical_false_positives(self, repo):
        secret_check = run_secret_detection(repo)
        # NestJS samples/ and test files contain intentional demo passwords —
        # these are downgraded to LOW by the test-file exclusion logic.
        critical = [f for f in secret_check.findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 0, \
            f"False positive CRITICAL secrets in nestjs: {[f.title + ' @ ' + str(f.location) for f in critical[:5]]}"

    def test_scan_completes_under_60s(self, repo):
        t0 = time.perf_counter()
        run_sast(repo)
        run_secret_detection(repo)
        elapsed = time.perf_counter() - t0
        assert elapsed < 60, f"NestJS scan took {elapsed:.1f}s"


# ─────────────────────────────────────────────────────────────────────────────
#  4. got — smaller TS HTTP library
# ─────────────────────────────────────────────────────────────────────────────

class TestGot:

    @pytest.fixture(scope="class")
    def repo(self):
        path = _clone("https://github.com/sindresorhus/got.git", "got")
        if not path:
            pytest.skip("Could not clone got")
        return path

    def test_detected_as_node_project(self, repo):
        assert _is_node_project(repo)

    def test_package_json_edge_cases(self, repo):
        """got uses esm-only package.json patterns — parser should not crash."""
        pkgs = _parse_package_json(repo / "package.json")
        # Should parse without exception and return some packages
        assert isinstance(pkgs, list)

    def test_no_critical_sast_false_positives(self, repo):
        check = run_sast(repo)
        critical = [f for f in check.findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 0

    def test_scan_fast_on_small_repo(self, repo):
        t0 = time.perf_counter()
        run_sast(repo)
        run_secret_detection(repo)
        elapsed = time.perf_counter() - t0
        assert elapsed < 15


# ─────────────────────────────────────────────────────────────────────────────
#  5. Controlled vulnerability injection
#     Take node_clean (APPROVE baseline) → inject one vuln → verify BLOCK
# ─────────────────────────────────────────────────────────────────────────────

class TestControlledVulnerabilityInjection:

    @pytest.fixture
    def baseline(self):
        """Verify node_clean is clean before we inject anything."""
        src = SAMPLE_DIR / "node_clean"
        if not src.exists():
            pytest.skip("node_clean sample project not found")
        return src

    @pytest.fixture
    def injected_eval(self, tmp_path, baseline):
        """Copy node_clean and inject a CRITICAL eval() vulnerability."""
        dest = tmp_path / "injected_eval"
        shutil.copytree(baseline, dest)
        vuln_code = '\n// INJECTED: eval on user input\napp.post("/run", (req, res) => {\n  const r = eval(req.body.code);\n  res.json({ r });\n});\n'
        app_js = dest / "app.js"
        app_js.write_text(app_js.read_text() + vuln_code)
        return dest

    @pytest.fixture
    def injected_secret(self, tmp_path, baseline):
        """Copy node_clean and inject a hardcoded API key."""
        dest = tmp_path / "injected_secret"
        shutil.copytree(baseline, dest)
        secret_code = '\nconst api_key = "sk-prod-abc123def456ghi789jkl0";\n'
        app_js = dest / "app.js"
        app_js.write_text(app_js.read_text() + secret_code)
        return dest

    @pytest.fixture
    def injected_vuln_dep(self, tmp_path, baseline):
        """Copy node_clean and inject a known-vulnerable lodash version."""
        dest = tmp_path / "injected_dep"
        shutil.copytree(baseline, dest)
        pkg = json.loads((dest / "package.json").read_text())
        pkg["dependencies"]["lodash"] = "4.17.15"   # CVE-2021-23337
        (dest / "package.json").write_text(json.dumps(pkg, indent=2))
        return dest

    # ── Baseline: clean project approves ─────────────────────────────────────

    def test_baseline_is_approved(self, baseline):
        result = run_analysis(baseline, "node_clean_baseline")
        assert result.decision != Decision.BLOCK, "Baseline should not be BLOCK"

    # ── Injection: eval → SAST finding → BLOCK ────────────────────────────────

    def test_injected_eval_is_detected(self, injected_eval):
        check = run_sast(injected_eval)
        titles = [f.title.lower() for f in check.findings]
        assert any("eval" in t for t in titles), "eval() not detected after injection"

    def test_injected_eval_triggers_block(self, injected_eval):
        result = run_analysis(injected_eval, "injected-eval")
        assert result.decision == Decision.BLOCK
        assert result.trust_score < 50

    def test_injected_eval_has_evidence_chain(self, injected_eval):
        """The full evidence chain: SAST finding → decision reason → certificate."""
        result = run_analysis(injected_eval, "injected-eval")
        # Finding in SAST check
        sast = next(c for c in result.checks if "SAST" in c.check_name or "Static" in c.check_name)
        assert any("eval" in f.title.lower() for f in sast.findings)
        # Decision reason references it
        assert any("HIGH" in r or "eval" in r.lower() for r in result.decision_reasons)
        # Certificate still generated
        assert result.certificate_id is not None
        assert result.certificate_hash is not None

    def test_injected_eval_provenance_reflects_failure(self, injected_eval):
        result = run_analysis(injected_eval, "injected-eval")
        assert result.provenance is not None
        statuses = [n.status for n in result.provenance.nodes]
        assert "FAIL" in statuses

    # ── Injection: secret → CRITICAL finding → BLOCK ─────────────────────────

    def test_injected_secret_is_detected(self, injected_secret):
        check = run_secret_detection(injected_secret)
        assert check.status == CheckStatus.FAIL
        critical = [f for f in check.findings if f.severity == Severity.CRITICAL]
        assert len(critical) > 0

    def test_injected_secret_triggers_block(self, injected_secret):
        result = run_analysis(injected_secret, "injected-secret")
        assert result.decision == Decision.BLOCK

    def test_injected_secret_certificate_differs_from_baseline(self, baseline, injected_secret):
        """Different evidence must produce a different certificate hash."""
        r_baseline = run_analysis(baseline, "clean")
        r_injected = run_analysis(injected_secret, "injected")
        assert r_baseline.certificate_hash != r_injected.certificate_hash

    # ── Injection: vulnerable dep → finding → decision ────────────────────────

    def test_injected_vuln_dep_detected(self, injected_vuln_dep):
        check = run_dependency_scan(injected_vuln_dep)
        # lodash 4.17.15 has real CVEs — should fail when online
        assert check.check_name == "Dependency Analysis"
        # Don't assert FAIL — network may be unavailable in CI
        # But if findings exist, they must have correct schema
        for f in check.findings:
            assert f.severity in list(Severity)
            assert "lodash" in f.title.lower() or "lodash" in (f.location or "").lower()

    def test_injected_vuln_dep_goes_through_decision_engine(self, injected_vuln_dep):
        result = run_analysis(injected_vuln_dep, "injected-dep")
        # Decision engine must run — result must have a valid decision
        assert result.decision in list(Decision)
        assert result.certificate_id is not None


# ─────────────────────────────────────────────────────────────────────────────
#  6. Package.json version range edge cases
# ─────────────────────────────────────────────────────────────────────────────

class TestVersionRangeEdgeCases:
    """
    Verifies _parse_package_json handles all real-world version formats
    without producing misleading vulnerability results.
    """

    def _make_pkg(self, tmp_path, deps: dict) -> Path:
        f = tmp_path / "package.json"
        f.write_text(json.dumps({"name": "test", "version": "1.0.0", "dependencies": deps}))
        return tmp_path

    def test_caret_range_stripped(self, tmp_path):
        p = self._make_pkg(tmp_path, {"react": "^19.0.0"})
        pkgs = _parse_package_json(p / "package.json")
        assert pkgs[0] == ("react", "19.0.0", "npm")

    def test_tilde_range_stripped(self, tmp_path):
        p = self._make_pkg(tmp_path, {"lodash": "~4.17.21"})
        pkgs = _parse_package_json(p / "package.json")
        assert pkgs[0] == ("lodash", "4.17.21", "npm")

    def test_gte_range_stripped(self, tmp_path):
        p = self._make_pkg(tmp_path, {"express": ">=4.18.0"})
        pkgs = _parse_package_json(p / "package.json")
        assert pkgs[0] == ("express", "4.18.0", "npm")

    def test_wildcard_skipped(self, tmp_path):
        p = self._make_pkg(tmp_path, {"some-pkg": "*"})
        pkgs = _parse_package_json(p / "package.json")
        assert len(pkgs) == 0

    def test_latest_tag_skipped(self, tmp_path):
        p = self._make_pkg(tmp_path, {"some-pkg": "latest"})
        pkgs = _parse_package_json(p / "package.json")
        assert len(pkgs) == 0

    def test_git_url_skipped(self, tmp_path):
        p = self._make_pkg(tmp_path, {"my-lib": "git+https://github.com/user/repo.git"})
        pkgs = _parse_package_json(p / "package.json")
        assert len(pkgs) == 0

    def test_github_shorthand_skipped(self, tmp_path):
        p = self._make_pkg(tmp_path, {"my-lib": "user/repo"})
        pkgs = _parse_package_json(p / "package.json")
        assert len(pkgs) == 0

    def test_file_protocol_skipped(self, tmp_path):
        p = self._make_pkg(tmp_path, {"local-pkg": "file:../local-pkg"})
        pkgs = _parse_package_json(p / "package.json")
        assert len(pkgs) == 0

    def test_mixed_valid_and_invalid_only_returns_valid(self, tmp_path):
        p = self._make_pkg(tmp_path, {
            "express": "^4.21.2",
            "my-git-pkg": "git+https://github.com/user/pkg.git",
            "local": "file:../local",
            "star-pkg": "*",
            "lodash": "4.17.21",
        })
        pkgs = _parse_package_json(p / "package.json")
        names = [p[0] for p in pkgs]
        assert "express" in names
        assert "lodash" in names
        assert "my-git-pkg" not in names
        assert "local" not in names
        assert "star-pkg" not in names

    def test_complex_range_takes_lower_bound(self, tmp_path):
        """>=1.0.0 <2.0.0 — should take 1.0.0, not crash."""
        p = self._make_pkg(tmp_path, {"semver": ">=1.0.0 <2.0.0"})
        pkgs = _parse_package_json(p / "package.json")
        assert pkgs[0][1] == "1.0.0"

    def test_no_version_produces_no_misleading_result(self, tmp_path):
        """Packages we can't resolve a version for should be skipped, not falsely flagged."""
        p = self._make_pkg(tmp_path, {"weird-pkg": "custom-registry:1.0"})
        pkgs = _parse_package_json(p / "package.json")
        # Either skipped or parsed — must not raise
        assert isinstance(pkgs, list)


# ─────────────────────────────────────────────────────────────────────────────
#  7. CLI JSON output validation
# ─────────────────────────────────────────────────────────────────────────────

class TestCliJsonOutput:

    def test_cli_json_output_is_valid_for_node_project(self):
        """cato analyze --json must produce parseable JSON for a Node project."""
        src = SAMPLE_DIR / "node_unsafe"
        if not src.exists():
            pytest.skip("node_unsafe not found")

        result = subprocess.run(
            ["cato", "analyze", str(src), "--json"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 2 and not result.stdout:
            # cato not on PATH in this environment — try python -m
            cato_cli = Path(__file__).parent.parent.parent / "cli"
            result = subprocess.run(
                [sys.executable, "-m", "cato_cli.main", "analyze", str(src), "--json"],
                capture_output=True, text=True, timeout=60,
                cwd=str(cato_cli),
                env={**__import__("os").environ, "PYTHONPATH": str(cato_cli)},
            )

        output = result.stdout.strip()
        if not output:
            pytest.skip(f"CLI produced no output (stderr: {result.stderr[:200]})")

        try:
            parsed = json.loads(output)
        except json.JSONDecodeError as e:
            pytest.fail(f"CLI --json output is not valid JSON: {e}\nOutput: {output[:500]}")

        assert "decision" in parsed
        assert "trust_score" in parsed
        assert "checks" in parsed
        assert "certificate_id" in parsed

    def test_cli_json_output_is_valid_for_python_project(self):
        src = SAMPLE_DIR / "clean_api"
        if not src.exists():
            pytest.skip("clean_api not found")

        result = subprocess.run(
            ["cato", "analyze", str(src), "--json"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 2 and not result.stdout:
            cato_cli = Path(__file__).parent.parent.parent / "cli"
            result = subprocess.run(
                [sys.executable, "-m", "cato_cli.main", "analyze", str(src), "--json"],
                capture_output=True, text=True, timeout=60,
                cwd=str(cato_cli),
                env={**__import__("os").environ, "PYTHONPATH": str(cato_cli)},
            )

        output = result.stdout.strip()
        if not output:
            pytest.skip(f"CLI produced no output (stderr: {result.stderr[:200]})")

        parsed = json.loads(output)
        assert parsed["decision"] == "APPROVE"


# ─────────────────────────────────────────────────────────────────────────────
#  8. Summary table (runs after all tests, always prints)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def print_summary_table():
    """Collect static-only scan results from all available repos and print table."""
    yield  # run all tests first

    rows = []
    repos_to_scan = {
        "express":      REPOS_DIR / "express",
        "fastify":      REPOS_DIR / "fastify",
        "nestjs":       REPOS_DIR / "nestjs",
        "got":          REPOS_DIR / "got",
        "node_unsafe":  SAMPLE_DIR / "node_unsafe",
        "node_clean":   SAMPLE_DIR / "node_clean",
        "ts_api":       SAMPLE_DIR / "ts_api",
        "clean_api":    SAMPLE_DIR / "clean_api",
        "unsafe_app":   SAMPLE_DIR / "unsafe_app",
    }

    for name, path in repos_to_scan.items():
        if not path.exists():
            continue
        try:
            row = _scan_static_only(path, name)
            rows.append(row)
        except Exception as e:
            rows.append({
                "name": name, "lang": "?", "is_node": False,
                "pkg_count": 0, "dep_status": "ERR", "dep_findings": 0,
                "sast_status": "ERR", "sast_findings": 0,
                "secret_status": "ERR", "secret_findings": 0,
                "critical_n": 0, "high_n": 0, "elapsed_ms": 0,
            })

    if rows:
        _print_table(rows)
