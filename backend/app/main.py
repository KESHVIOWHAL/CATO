"""
CATO — Context-Aware Trust Orchestrator
Full architecture implementation:
  Developer Input → AI Protection → Sanitization & Routing → Analysis Pipeline
  → Evidence & Provenance Graph → Trust Decision → Certificate → Blockchain
"""

import json
import shutil
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from blockchain import registry
from certificate import generate_certificate
from decision_engine import make_decision
from models import (
    AIProtectionResult, AnalysisRequest, AnalysisResult,
    ProtectionFindingModel, TrustCertificate
)
from scanner import (
    BASE_DIR, _collect_source_files, _tool_available,
    run_dependency_scan, run_functional_tests, run_sast, run_secret_detection,
)
from requirement_checker import run_requirement_check
from architecture_checker import run_architecture_check
from ai_protection import analyze_input
from provenance_graph import build_provenance_graph
from comparison import compare_direct_vs_cato, run_benchmark, run_size_benchmark, DEFAULT_DEMO_PROMPT
from inline_analyzer import analyze_inline

app = FastAPI(title="CATO — Context-Aware Trust Orchestrator", version="0.2.0")

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

certificate_store: dict = {}


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _resolve_path(project_path: str) -> Path:
    p = Path(project_path)
    if p.is_absolute() and p.exists():
        return p
    candidate = BASE_DIR / project_path
    if candidate.exists():
        return candidate
    raise ValueError(f"Project path not found: {project_path}")


def _load_policy(project_path: Path) -> dict:
    policy_file = project_path / "cato-policy.json"
    if policy_file.exists():
        try:
            return json.loads(policy_file.read_text())
        except Exception:
            pass
    return {}


def _run_full_analysis(
    project_path: Path,
    project_name: str,
    project_path_label: str,
    project_context: str = "",
) -> AnalysisResult:
    import time
    timestamp = datetime.now(timezone.utc).isoformat()
    policy_config = _load_policy(project_path)
    files_scanned = len(_collect_source_files(project_path))

    # ── POST-AI layer: run all 6 checks with per-stage timing ──
    stage_times: dict = {}

    def timed(fn, *args):
        t0 = time.perf_counter()
        r  = fn(*args)
        stage_times[r.check_name] = round((time.perf_counter() - t0) * 1000, 1)
        return r

    t_post_start = time.perf_counter()

    req_check    = timed(run_requirement_check,  project_path, project_context)
    arch_check   = timed(run_architecture_check, project_path, policy_config)
    secret_check = timed(run_secret_detection,   project_path)
    dep_check    = timed(run_dependency_scan,    project_path)
    sast_check   = timed(run_sast,               project_path)
    test_check   = timed(run_functional_tests,   project_path)

    post_ai_total_ms = round((time.perf_counter() - t_post_start) * 1000, 1)

    all_checks = [req_check, arch_check, secret_check, dep_check, sast_check, test_check]

    decision, risk_level, trust_score, reasons, policy, recommendations = make_decision(
        all_checks, policy_config
    )

    graph = build_provenance_graph(all_checks, req_check, arch_check)

    from models import ProvenanceGraphModel, ProvenanceNodeModel
    provenance_model = ProvenanceGraphModel(
        nodes=[ProvenanceNodeModel(**n.to_dict()) for n in graph.nodes],
        traceable=graph.traceable,
        stages=graph.stages,
    )

    result = AnalysisResult(
        project_name=project_name,
        project_path=project_path_label,
        timestamp=timestamp,
        checks=all_checks,
        decision=decision,
        risk_level=risk_level,
        trust_score=trust_score,
        decision_reasons=reasons,
        policy=policy,
        recommendations=recommendations,
        provenance=provenance_model,
        files_scanned=files_scanned,
        post_ai_stage_ms=stage_times,
        post_ai_total_ms=post_ai_total_ms,
    )

    cert = generate_certificate(result)
    bc = registry.register(cert.certificate_hash, cert.certificate_id)
    cert.blockchain_tx = bc["tx_hash"]
    cert.blockchain_status = "RECORDED"
    certificate_store[cert.certificate_id] = cert

    result.certificate_id   = cert.certificate_id
    result.certificate_hash = cert.certificate_hash
    result.blockchain_tx    = bc["tx_hash"]
    result.blockchain_status = "RECORDED"
    return result


# ─────────────────────────────────────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"service": "CATO", "status": "running", "version": "0.2.0-prototype"}


@app.get("/scanner-status")
def scanner_status():
    import urllib.request
    network_ok = False
    try:
        urllib.request.urlopen("https://api.osv.dev", timeout=3)
        network_ok = True
    except Exception:
        pass
    return {
        "gitleaks": _tool_available("gitleaks"),
        "semgrep": _tool_available("semgrep"),
        "osv_scanner_binary": _tool_available("osv-scanner"),
        "osv_api_network": network_ok,
        "pytest": True,
        "builtin_secret_scanner": True,
        "builtin_sast": True,
        "requirement_checker": True,
        "architecture_checker": True,
        "ai_protection": True,
        "provenance_graph": True,
    }


@app.get("/projects")
def list_projects():
    META = {
        "unsafe_app":     {"desc": "Unsafe AI-generated code with hardcoded secrets and injection flaws",  "expected": "BLOCK"},
        "fixed_app":      {"desc": "Remediated version — all security issues resolved",                    "expected": "APPROVE"},
        "ecommerce_app":  {"desc": "Vulnerable e-commerce app: SQL injection, hardcoded API keys, unsafe deps", "expected": "BLOCK"},
        "clean_api":      {"desc": "Secure REST API: parameterized queries, env-based secrets, clean deps", "expected": "APPROVE"},
        "medium_risk":    {"desc": "Medium-risk app: weak hash, unsafe assert, no secrets",                "expected": "REVIEW"},
        "complex_app":    {"desc": "Multi-module app with auth, DB, API, services, models, tests",         "expected": "BLOCK"},
    }
    projects = []
    for d in sorted(BASE_DIR.iterdir()):
        if d.is_dir():
            m = META.get(d.name, {})
            projects.append({
                "id":          d.name,
                "name":        d.name.replace("_", " ").title(),
                "path":        d.name,
                "description": m.get("desc", "Demo project"),
                "expected":    m.get("expected", ""),
            })
    return {"projects": projects}


@app.post("/evaluate-suite")
def evaluate_suite():
    """Run CATO analysis on all demo projects and return comparison table."""
    import time
    suite_projects = ["ecommerce_app", "clean_api", "medium_risk", "complex_app"]
    results = []
    for proj_id in suite_projects:
        try:
            path = _resolve_path(proj_id)
            t0   = time.perf_counter()
            r    = _run_full_analysis(path, proj_id.replace("_", " ").title(), proj_id, "")
            elapsed = round((time.perf_counter() - t0), 2)
            results.append({
                "id":          proj_id,
                "name":        proj_id.replace("_", " ").title(),
                "files":       r.files_scanned,
                "findings":    sum(len(c.findings) for c in r.checks),
                "critical":    sum(1 for c in r.checks for f in c.findings if f.severity.value == "CRITICAL"),
                "high":        sum(1 for c in r.checks for f in c.findings if f.severity.value == "HIGH"),
                "medium":      sum(1 for c in r.checks for f in c.findings if f.severity.value == "MEDIUM"),
                "tests":       next((c.status.value for c in r.checks if "Test" in c.check_name), "SKIP"),
                "decision":    r.decision.value,
                "trust_score": r.trust_score,
                "elapsed_s":   elapsed,
                "cert_id":     r.certificate_id,
            })
        except Exception as e:
            results.append({"id": proj_id, "error": str(e)})
    return {"results": results}


@app.post("/analyze", response_model=AnalysisResult)
def analyze_project(request: AnalysisRequest):
    try:
        project_path = _resolve_path(request.project_path)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _run_full_analysis(
        project_path, request.project_name,
        request.project_path, request.project_context or ""
    )


@app.post("/protect")
def check_input_protection(payload: dict):
    """AI Interaction Protection — analyze raw developer input before AI routing."""
    import time
    text   = payload.get("text", "")
    policy = payload.get("policy", {})
    if not text:
        raise HTTPException(status_code=400, detail="text field required")

    t0 = time.perf_counter()
    result = analyze_input(text, policy)
    total_ms = round((time.perf_counter() - t0) * 1000, 2)

    d = result.to_dict()
    d["total_ms"] = total_ms
    d["prompt_size_bytes"] = len(text.encode("utf-8"))
    return d


@app.post("/upload", response_model=AnalysisResult)
async def upload_and_analyze(
    project_name: str = Form(...),
    source_zip: UploadFile = File(...),
    policy_json: str = Form(default="{}"),
    architecture_notes: str = Form(default=""),
):
    if not source_zip.filename or not source_zip.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip files are supported")

    tmp_dir = Path(tempfile.mkdtemp(prefix="cato_upload_"))
    try:
        zip_bytes = await source_zip.read()
        zip_path  = tmp_dir / "upload.zip"
        zip_path.write_bytes(zip_bytes)

        extract_dir = tmp_dir / "project"
        extract_dir.mkdir()

        with zipfile.ZipFile(zip_path, "r") as zf:
            for member in zf.namelist():
                dest = (extract_dir / member).resolve()
                if not str(dest).startswith(str(extract_dir.resolve())):
                    raise HTTPException(status_code=400, detail="Unsafe ZIP path detected")
            zf.extractall(extract_dir)

        entries = list(extract_dir.iterdir())
        project_root = entries[0] if len(entries) == 1 and entries[0].is_dir() else extract_dir

        try:
            policy_data = json.loads(policy_json)
        except Exception:
            policy_data = {}
        if architecture_notes.strip():
            policy_data["architecture_notes"] = architecture_notes.strip()
        if policy_data:
            (project_root / "cato-policy.json").write_text(json.dumps(policy_data))

        return _run_full_analysis(
            project_root, project_name,
            f"upload:{source_zip.filename}", architecture_notes
        )
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@app.get("/certificate/{cert_id}", response_model=TrustCertificate)
def get_certificate(cert_id: str):
    cert = certificate_store.get(cert_id)
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return cert


@app.get("/verify/{cert_hash}")
def verify_certificate(cert_hash: str):
    return registry.verify(cert_hash)


@app.get("/blockchain/chain")
def get_chain():
    return {
        "chain": registry.get_chain(),
        "length": len(registry.get_chain()),
        "valid": registry.is_chain_valid(),
        "mode": "Prototype Blockchain Registry (In-Memory SHA-256 Chain)",
    }


# ─────────────────────────────────────────────────────────────────────────────
#  FEATURE 1 — AI vs CATO COMPARISON
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/compare")
def compare_ai_vs_cato(payload: dict):
    """
    Compare direct AI prompt transmission vs CATO-protected routing.
    No real credentials are transmitted externally.
    """
    prompt   = payload.get("prompt", DEFAULT_DEMO_PROMPT)
    ai_model = payload.get("ai_model", "claude")
    policy   = payload.get("policy", {})
    if not prompt.strip():
        raise HTTPException(status_code=400, detail="prompt is required")
    return compare_direct_vs_cato(prompt, ai_model, policy)


@app.get("/compare/demo-prompt")
def get_demo_prompt():
    return {"prompt": DEFAULT_DEMO_PROMPT}


@app.get("/timing/pre-ai")
def pre_ai_timing():
    """Measure actual pre-AI protection layer timing across small/medium/large prompts."""
    from comparison import run_protected, BENCHMARK_PROMPTS
    import statistics

    result = {}
    for size, prompt in BENCHMARK_PROMPTS.items():
        times = []
        stage_acc: dict[str, list] = {}
        for _ in range(10):
            _, lat = run_protected(prompt)
            d = lat.to_dict()
            times.append(d["total_ms"])
            for stage, ms in lat.stages.items():
                stage_acc.setdefault(stage, []).append(ms)

        result[size] = {
            "prompt_size_kb":     round(len(prompt.encode()) / 1024, 2),
            "avg_ms":             round(statistics.mean(times), 2),
            "median_ms":          round(statistics.median(times), 2),
            "min_ms":             round(min(times), 2),
            "max_ms":             round(max(times), 2),
            "stage_avg_ms":       {s: round(statistics.mean(v), 2) for s, v in stage_acc.items()},
        }
    return {
        "layer":       "PRE-AI (Prompt Protection Pipeline)",
        "description": "Time to inspect, sanitize, and route a developer prompt before it reaches any AI model.",
        "results":     result,
    }


@app.get("/timing/post-ai")
def post_ai_timing():
    """Return actual measured post-AI pipeline times from the last analysis run on each demo project."""
    project_times = []
    for proj_id in ["ecommerce_app", "clean_api", "medium_risk"]:
        try:
            path = _resolve_path(proj_id)
            result = _run_full_analysis(path, proj_id, proj_id, "")
            project_times.append({
                "project":         proj_id,
                "files_scanned":   result.files_scanned,
                "total_ms":        result.post_ai_total_ms,
                "total_s":         round(result.post_ai_total_ms / 1000, 2),
                "stage_ms":        result.post_ai_stage_ms,
                "decision":        result.decision.value,
            })
        except Exception as e:
            project_times.append({"project": proj_id, "error": str(e)})

    return {
        "layer":       "POST-AI (Software Verification Pipeline)",
        "description": "Time to run all 6 security checks after AI-generated code is produced.",
        "note":        "Dominated by network I/O to OSV.dev API and pytest execution. Scales with project size.",
        "results":     project_times,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  INLINE CODE ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/analyze-inline")
def analyze_inline_code(payload: dict):
    """
    Analyze raw pasted code through the full CATO pipeline.
    No ZIP required — just paste code directly.
    """
    code = payload.get("code", "").strip()
    if not code:
        raise HTTPException(status_code=400, detail="code field is required")

    language     = payload.get("language", "python")
    filename     = payload.get("filename", "pasted_code.py")
    requirements = payload.get("requirements", "")
    context      = payload.get("context", "")
    policy       = payload.get("policy", None)

    return analyze_inline(
        code=code,
        language=language,
        filename=filename,
        requirements=requirements,
        context_notes=context,
        policy_override=policy,
    )


# ─────────────────────────────────────────────────────────────────────────────
#  FEATURE 2 — LATENCY BENCHMARK
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/benchmark")
def benchmark_latency(payload: dict):
    """Run actual timed benchmark. All values from time.perf_counter()."""
    prompt = payload.get("prompt", DEFAULT_DEMO_PROMPT)
    runs   = min(int(payload.get("runs", 20)), 100)  # cap at 100
    return run_benchmark(prompt, runs)


@app.get("/benchmark/sizes")
def benchmark_sizes():
    """Run benchmark across small/medium/large prompts."""
    return run_size_benchmark()
