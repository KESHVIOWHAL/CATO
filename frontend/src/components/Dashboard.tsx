import { useState, useEffect, useRef } from "react";
import { analyzeProject, uploadAndAnalyze, getScannerStatus, listProjects } from "../api.ts";
import type { AnalysisResult, CheckResult, Finding, ScannerStatus, Recommendation } from "../api.ts";
import ProvenanceGraphView from "./ProvenanceGraph.tsx";
import "./Dashboard.css";

interface Props {
  result: AnalysisResult | null;
  setResult: (r: AnalysisResult) => void;
  onViewCert: () => void;
}

const ANALYSIS_STEPS = [
  "Project discovered",
  "Source files inspected",
  "Secret scan running…",
  "Static analysis running…",
  "Dependency analysis running…",
  "Functional tests running…",
  "Evidence correlated",
  "Policy evaluated",
  "Trust Certificate generated",
  "Blockchain record created",
];

// ── Trust score gauge ─────────────────────────────────────────────────────────
function TrustScore({ score, decision }: { score: number; decision: string }) {
  const color =
    decision === "BLOCK"   ? "var(--red)"   :
    decision === "REVIEW"  ? "var(--amber)" : "var(--green)";
  const label =
    score >= 80 ? "TRUSTED" : score >= 50 ? "MARGINAL" : "UNTRUSTED";
  const circumference = 2 * Math.PI * 36;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="trust-score-wrap">
      <svg width="100" height="100" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r="36" fill="none" stroke="var(--border)" strokeWidth="8" />
        <circle
          cx="50" cy="50" r="36" fill="none"
          stroke={color} strokeWidth="8"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform="rotate(-90 50 50)"
          style={{ transition: "stroke-dashoffset 0.8s ease" }}
        />
        <text x="50" y="47" textAnchor="middle" fill={color} fontSize="20" fontWeight="800">{score}</text>
        <text x="50" y="62" textAnchor="middle" fill="var(--text-muted)" fontSize="8" fontWeight="600">/100</text>
      </svg>
      <div className="trust-score-label" style={{ color }}>{label}</div>
      <div style={{ fontSize: 10, color: "var(--text-muted)" }}>Trust Score</div>
    </div>
  );
}

// ── Recommendations panel ─────────────────────────────────────────────────────
const CAT_ICON: Record<string, string> = {
  SECRET: "🔑", SAST: "🔬", DEPENDENCY: "📦", TEST: "🧪", POLICY: "📋",
};

function RecommendationsPanel({ recs }: { recs: Recommendation[] }) {
  const [open, setOpen] = useState<number | null>(0);
  if (recs.length === 0) return null;

  return (
    <div className="recs-panel card">
      <div className="section-title" style={{ marginBottom: 12 }}>
        🛠 Recommendations
        <span style={{ marginLeft: 8, fontWeight: 400, color: "var(--text-muted)" }}>
          — {recs.length} action{recs.length !== 1 ? "s" : ""} to resolve findings
        </span>
      </div>
      <div className="recs-list">
        {recs.map((rec, i) => (
          <div key={i} className={`rec-item rec-${rec.severity.toLowerCase()}`}>
            <button className="rec-header" onClick={() => setOpen(open === i ? null : i)}>
              <span className="rec-num">#{rec.priority}</span>
              <span className="rec-icon">{CAT_ICON[rec.category] ?? "🔍"}</span>
              <div className="rec-title-block">
                <span className="rec-title">{rec.title}</span>
                {rec.location && <span className="rec-loc">📍 {rec.location}</span>}
              </div>
              <span className={`sev-badge sev-${rec.severity.toLowerCase()}`} style={{ marginLeft: "auto", flexShrink: 0 }}>
                {rec.severity}
              </span>
              <span style={{ color: "var(--text-muted)", marginLeft: 8, fontSize: 12 }}>{open === i ? "▲" : "▼"}</span>
            </button>

            {open === i && (
              <div className="rec-body">
                <div className="rec-section">
                  <div className="rec-section-label">What is the problem?</div>
                  <div className="rec-section-text">{rec.what}</div>
                </div>
                <div className="rec-section">
                  <div className="rec-section-label">How to fix it</div>
                  <pre className="rec-fix">{rec.fix}</pre>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Evidence card ─────────────────────────────────────────────────────────────
function EvidenceCard({ check }: { check: CheckResult }) {
  const [open, setOpen] = useState(false);
  const isFail = check.status === "FAIL";
  const isPass = check.status === "PASS";
  const icon =
    check.check_name.includes("Secret")     ? "🔑" :
    check.check_name.includes("SAST")       ? "🔬" :
    check.check_name.includes("Dependency") ? "📦" :
    check.check_name.includes("Tests")      ? "🧪" : "🔍";

  return (
    <div className={`evidence-card ${isFail ? "ev-fail" : isPass ? "ev-pass" : "ev-skip"}`}>
      <div className="ev-header">
        <div className="ev-left">
          <span className="ev-icon">{icon}</span>
          <div>
            <div className="ev-name">{check.check_name}</div>
            <div className="ev-summary">{check.summary}</div>
          </div>
        </div>
        <div className="ev-right">
          <span className={`badge ${check.scan_mode === "LIVE" ? "badge-live" : "badge-demo"}`}>{check.scan_mode}</span>
          <span className={`badge ${isFail ? "badge-fail" : isPass ? "badge-pass" : "badge-skip"}`}>
            {isFail ? "✗ FAIL" : isPass ? "✓ PASS" : "– SKIP"}
          </span>
        </div>
      </div>
      {check.findings.length > 0 && (
        <>
          <button className="findings-toggle" onClick={() => setOpen(!open)}>
            {open ? "▲ Hide findings" : `▼ Show ${check.findings.length} finding(s)`}
          </button>
          {open && (
            <div className="findings-list">
              {check.findings.map((f: Finding, i: number) => (
                <div key={i} className={`finding finding-${f.severity.toLowerCase()}`}>
                  <div className="finding-title">
                    <span className={`sev-badge sev-${f.severity.toLowerCase()}`}>{f.severity}</span>
                    <span>{f.title}</span>
                  </div>
                  <div className="finding-desc">{f.description}</div>
                  {f.location && <div className="finding-loc">📍 {f.location}</div>}
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ── Scanner status bar ────────────────────────────────────────────────────────
function ScannerStatusBar({ status }: { status: ScannerStatus }) {
  const items = [
    { label: "Gitleaks",        active: status.gitleaks,         fallback: "Built-in regex" },
    { label: "Semgrep",         active: status.semgrep,          fallback: "Built-in AST" },
    { label: "OSV.dev API",     active: status.osv_api_network,  fallback: "Local CVE table" },
    { label: "pytest",          active: true,                    fallback: null },
  ];
  return (
    <div className="scanner-bar">
      <span className="scanner-bar-label">Scanners</span>
      {items.map((s, i) => (
        <div key={i} className={`scanner-pill ${s.active ? "pill-live" : "pill-fallback"}`}>
          <span>{s.active ? "●" : "○"}</span>
          <span>{s.label}</span>
          {!s.active && s.fallback && <span className="pill-note">→ {s.fallback}</span>}
        </div>
      ))}
    </div>
  );
}

// ── Analysis progress ─────────────────────────────────────────────────────────
function AnalysisProgress({ step, projectName }: { step: number; projectName: string }) {
  return (
    <div className="progress-box card">
      <div className="progress-title">
        <span className="spinner" />
        Analyzing <strong>{projectName}</strong>
      </div>
      <div className="progress-steps">
        {ANALYSIS_STEPS.map((s, i) => (
          <div key={i} className={`progress-step ${i < step ? "step-done" : i === step ? "step-active" : "step-pending"}`}>
            <span className="step-icon">{i < step ? "✓" : i === step ? "›" : "·"}</span>
            <span>{s}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Project selector modal ────────────────────────────────────────────────────
type Tab = "demo" | "upload";

interface DemoProject { id: string; name: string; path: string; description: string }

function ProjectSelector({
  onSelect,
  loading,
}: {
  onSelect: (name: string, path: string, file?: File, policy?: string, arch?: string) => void;
  loading: boolean;
}) {
  const [tab, setTab] = useState<Tab>("demo");

  // Demo tab
  const [demoProjects, setDemoProjects] = useState<DemoProject[]>([]);
  const [selectedDemo, setSelectedDemo] = useState<string>("");

  // Upload tab
  const [projectName, setProjectName] = useState("");
  const [zipFile, setZipFile] = useState<File | null>(null);
  const [policyText, setPolicyText] = useState(
    JSON.stringify({ critical_secret: "BLOCK", high_vulnerability: "BLOCK", medium_vulnerability: "REVIEW", failed_tests: "REVIEW" }, null, 2)
  );
  const [archNotes, setArchNotes] = useState("");
  const fileRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    listProjects().then(d => {
      setDemoProjects(d.projects);
      if (d.projects.length > 0) setSelectedDemo(d.projects[0].path);
    }).catch(() => {});
  }, []);

  function handleDemo() {
    const proj = demoProjects.find(p => p.path === selectedDemo);
    if (!proj) return;
    onSelect(proj.name, proj.path);
  }

  function handleUpload() {
    if (!projectName.trim()) return;
    if (!zipFile) return;
    onSelect(projectName.trim(), "", zipFile, policyText, archNotes);
  }

  const uploadReady = projectName.trim().length > 0 && zipFile !== null;

  return (
    <div className="selector-panel card">
      <div className="selector-header">
        <img src="/cato-logo.png" alt="CATO" style={{ width: 44, height: 44, borderRadius: "50%", border: "2px solid var(--amber-border)", flexShrink: 0 }} />
        <div>
          <div style={{ fontWeight: 700, fontSize: 16 }}>Select Project for Analysis</div>
          <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
            Use a demo project or upload your own source code
          </div>
        </div>
      </div>

      <div className="selector-tabs">
        <button className={`sel-tab ${tab === "demo" ? "sel-tab-active" : ""}`} onClick={() => setTab("demo")}>
          ◈ Demo Projects
        </button>
        <button className={`sel-tab ${tab === "upload" ? "sel-tab-active" : ""}`} onClick={() => setTab("upload")}>
          ↑ Upload Your Project
        </button>
      </div>

      {/* ── Demo tab ── */}
      {tab === "demo" && (
        <div className="sel-body">
          <div className="section-title">Choose a demo project</div>
          <div className="demo-project-list">
            {demoProjects.map(p => (
              <button
                key={p.path}
                className={`demo-proj-btn ${selectedDemo === p.path ? "active" : ""}`}
                onClick={() => setSelectedDemo(p.path)}
                disabled={loading}
              >
                <span className={`proj-dot ${p.path.includes("unsafe") ? "dot-red" : "dot-green"}`} />
                <div>
                  <div className="proj-name">{p.name}</div>
                  <div className="proj-meta">{p.description}</div>
                </div>
                {selectedDemo === p.path && <span style={{ marginLeft: "auto", color: "var(--accent)" }}>✓</span>}
              </button>
            ))}
          </div>
          <div className="demo-note-box">
            These are intentionally crafted sample projects. The <strong>Unsafe App</strong> contains hardcoded secrets, SQL injection, and vulnerable dependencies. The <strong>Fixed App</strong> has all issues remediated. CATO will reach its decision from real analysis — not from the project name.
          </div>
          <button className="btn btn-primary" style={{ width: "100%", marginTop: 16 }} onClick={handleDemo} disabled={loading || !selectedDemo}>
            {loading ? <><span className="spinner" /> Analyzing…</> : "⬡  Run CATO Analysis"}
          </button>
        </div>
      )}

      {/* ── Upload tab ── */}
      {tab === "upload" && (
        <div className="sel-body">
          <div className="upload-grid">
            {/* Project name */}
            <div className="upload-field">
              <label className="field-label">Project Name *</label>
              <input
                className="field-input"
                placeholder="e.g. MyApp v2.1"
                value={projectName}
                onChange={e => setProjectName(e.target.value)}
              />
            </div>

            {/* ZIP upload */}
            <div className="upload-field">
              <label className="field-label">Source Code (ZIP) *</label>
              <div
                className={`drop-zone ${zipFile ? "drop-zone-filled" : ""}`}
                onClick={() => fileRef.current?.click()}
                onDragOver={e => e.preventDefault()}
                onDrop={e => {
                  e.preventDefault();
                  const f = e.dataTransfer.files[0];
                  if (f?.name.endsWith(".zip")) setZipFile(f);
                }}
              >
                {zipFile
                  ? <><span style={{ fontSize: 20 }}>📦</span> <span>{zipFile.name}</span> <span style={{ color: "var(--text-muted)", fontSize: 11 }}>({(zipFile.size / 1024).toFixed(1)} KB)</span></>
                  : <><span style={{ fontSize: 24, display: "block", marginBottom: 6 }}>↑</span>
                    <span>Drop ZIP here or click to browse</span>
                    <span style={{ display: "block", fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
                      Zip your project folder. Python, JS, TS supported.
                    </span>
                  </>
                }
                <input ref={fileRef} type="file" accept=".zip" style={{ display: "none" }} onChange={e => { if (e.target.files?.[0]) setZipFile(e.target.files[0]); }} />
              </div>
            </div>

            {/* Policy JSON */}
            <div className="upload-field">
              <label className="field-label">
                Security Policy (JSON)
                <span className="field-optional"> — optional, edit or replace</span>
              </label>
              <textarea
                className="field-textarea"
                value={policyText}
                onChange={e => setPolicyText(e.target.value)}
                rows={6}
                spellCheck={false}
              />
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
                Keys: <code>critical_secret</code>, <code>high_vulnerability</code>, <code>medium_vulnerability</code>, <code>failed_tests</code> → values: BLOCK | REVIEW | APPROVE
              </div>
            </div>

            {/* Architecture notes */}
            <div className="upload-field">
              <label className="field-label">
                System Architecture / Context
                <span className="field-optional"> — optional</span>
              </label>
              <textarea
                className="field-textarea"
                placeholder="Describe your system architecture, compliance requirements, or any context CATO should know about. e.g. 'This is a public-facing API that handles PII. All secrets must be in environment variables. No shell commands allowed.'"
                value={archNotes}
                onChange={e => setArchNotes(e.target.value)}
                rows={4}
                spellCheck={false}
              />
            </div>
          </div>

          <button
            className="btn btn-primary"
            style={{ width: "100%", marginTop: 16 }}
            onClick={handleUpload}
            disabled={loading || !uploadReady}
          >
            {loading
              ? <><span className="spinner" /> Uploading & Analyzing…</>
              : uploadReady
                ? "⬡  Upload & Run CATO Analysis"
                : "Fill in project name and upload a ZIP to continue"
            }
          </button>
        </div>
      )}
    </div>
  );
}

// ── Main Dashboard ────────────────────────────────────────────────────────────
export default function Dashboard({ result, setResult, onViewCert }: Props) {
  const [loading, setLoading]             = useState(false);
  const [progressStep, setProgressStep]   = useState(0);
  const [analyzingName, setAnalyzingName] = useState("");
  const [error, setError]                 = useState<string | null>(null);
  const [scannerStatus, setScannerStatus] = useState<ScannerStatus | null>(null);
  const [showSelector, setShowSelector]   = useState(!result);

  useEffect(() => {
    getScannerStatus().then(setScannerStatus).catch(() => null);
  }, []);

  async function handleSelect(name: string, path: string, file?: File, policy?: string, arch?: string) {
    setLoading(true);
    setProgressStep(0);
    setError(null);
    setAnalyzingName(name || file?.name || path);

    const interval = setInterval(() => {
      setProgressStep(prev => (prev < 6 ? prev + 1 : prev));
    }, 420);

    try {
      let r: AnalysisResult;
      if (file) {
        r = await uploadAndAnalyze(name, file, policy ?? "{}", arch ?? "");
      } else {
        r = await analyzeProject(name, path);
      }
      clearInterval(interval);
      for (let s = 7; s <= ANALYSIS_STEPS.length - 1; s++) {
        await new Promise(res => setTimeout(res, 180));
        setProgressStep(s);
      }
      await new Promise(res => setTimeout(res, 280));
      setResult(r);
      setShowSelector(false);
    } catch (e: unknown) {
      clearInterval(interval);
      setError(e instanceof Error ? e.message : "Analysis failed — is the backend running on port 8000?");
    } finally {
      setLoading(false);
    }
  }

  const decisionClass =
    result?.decision === "BLOCK"   ? "decision-block"  :
    result?.decision === "REVIEW"  ? "decision-review" :
    result?.decision === "APPROVE" ? "decision-approve" : "";

  const decisionColor =
    result?.decision === "BLOCK"   ? "var(--red)"   :
    result?.decision === "REVIEW"  ? "var(--amber)" :
    result?.decision === "APPROVE" ? "var(--green)" : "var(--text)";

  const totalFindings = result?.checks.reduce((n, c) => n + c.findings.length, 0) ?? 0;

  return (
    <div className="dashboard">

      {/* ── Analyze another button (shown after result) ── */}
      {result && !loading && (
        <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 12 }}>
          <button className="btn btn-outline" onClick={() => setShowSelector(true)}>
            + Analyze Another Project
          </button>
        </div>
      )}

      {/* ── Project selector ── */}
      {showSelector && !loading && (
        <ProjectSelector onSelect={handleSelect} loading={loading} />
      )}

      {/* ── Scanner status (below selector, above results) ── */}
      {scannerStatus && showSelector && !loading && (
        <div className="card" style={{ marginTop: 12 }}>
          <ScannerStatusBar status={scannerStatus} />
        </div>
      )}

      {error && (
        <div className="error-msg" style={{ marginTop: 12 }}>⚠ {error}</div>
      )}

      {/* ── Analysis progress ── */}
      {loading && (
        <div style={{ marginTop: 16 }}>
          <AnalysisProgress step={progressStep} projectName={analyzingName} />
        </div>
      )}

      {/* ── Results ── */}
      {result && !loading && (
        <>
          {/* Decision banner */}
          <div className={`card decision-card ${decisionClass}`} style={{ marginTop: showSelector ? 16 : 0 }}>
            <div className="section-title" style={{ marginBottom: 10 }}>CATO TRUST DECISION</div>
            <div className="decision-row">
              <div className="decision-word" style={{ color: decisionColor }}>{result.decision}</div>
              <div className="decision-meta">
                <div className="decision-risk" style={{ color: decisionColor }}>{result.risk_level}</div>
                {/* REVIEW → Human Approval */}
                {result.decision === "REVIEW" && (
                  <div className="review-notice">
                    ⚠ REVIEW → Human Approval Required before deployment
                  </div>
                )}
                {/* BLOCK → Stop / Quarantine */}
                {result.decision === "BLOCK" && (
                  <div className="block-notice">
                    🚫 STOP / QUARANTINE — Software does not proceed
                  </div>
                )}
                <div className="decision-detail">
                  {result.project_name} · {result.files_scanned} file(s) scanned · {totalFindings} finding(s) across 6 checks
                </div>
                <div className="decision-detail">{new Date(result.timestamp).toLocaleString()}</div>
              </div>
              <div style={{ marginLeft: "auto" }}>
                <TrustScore score={result.trust_score} decision={result.decision} />
              </div>
            </div>
          </div>

          <div className="results-grid" style={{ marginTop: 16 }}>
            {/* LEFT: Evidence + Why */}
            <div>
              <div className="section-title" style={{ marginBottom: 10 }}>
                Security Evidence
                <span style={{ marginLeft: 8, fontWeight: 400, color: "var(--text-muted)" }}>
                  — {result.checks.length} scanners ran
                </span>
              </div>
              <div className="evidence-list">
                {result.checks.map((c: CheckResult, i: number) => <EvidenceCard key={i} check={c} />)}
              </div>

              <div className="card" style={{ marginTop: 14 }}>
                <div className="section-title">Why did CATO reach this decision?</div>
                <ul className="reasons-list">
                  {result.decision_reasons.map((r: string, i: number) => {
                    const isCrit  = r.startsWith("[CRITICAL]");
                    const isHigh  = r.startsWith("[HIGH]");
                    const isArrow = r.startsWith("→");
                    return (
                      <li key={i} className="reason-item">
                        <span className="reason-bullet" style={{
                          color: isCrit ? "var(--red)" : isHigh ? "#f97316" : isArrow ? decisionColor : "var(--accent)"
                        }}>
                          {isArrow ? "→" : "•"}
                        </span>
                        <span style={{ color: isArrow ? decisionColor : undefined, fontWeight: isArrow ? 600 : undefined }}>
                          {r.replace(/^→\s*/, "")}
                        </span>
                      </li>
                    );
                  })}
                </ul>
              </div>

              {/* Recommendations */}
              {result.recommendations.length > 0 && (
                <RecommendationsPanel recs={result.recommendations} />
              )}

              {/* Provenance Graph */}
              {result.provenance && (
                <ProvenanceGraphView graph={result.provenance} />
              )}
            </div>

            {/* RIGHT: Policy + Certificate + Blockchain */}
            <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              <div className="card">
                <div className="section-title">Policy Status</div>
                <div className={`policy-result ${result.policy.passed ? "policy-pass" : "policy-fail"}`}>
                  <span className="policy-icon">{result.policy.passed ? "✓" : "✗"}</span>
                  <span className="policy-label">{result.policy.passed ? "PASSED" : "FAILED"}</span>
                </div>
                <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 8 }}>
                  {result.policy.passed
                    ? "All security requirements met"
                    : "One or more security requirements violated"}
                </div>
              </div>

              {result.certificate_id && (
                <div className="card">
                  <div className="section-title">Trust Certificate</div>
                  <div className="cert-id-row">
                    <span style={{ fontSize: 11, color: "var(--text-muted)" }}>ID</span>
                    <span className="cert-id-val">{result.certificate_id}</span>
                  </div>

                  <div className="section-title" style={{ marginTop: 14 }}>SHA-256 Hash</div>
                  <div className="hash-box">{result.certificate_hash}</div>
                  <div className="hash-note">
                    Cryptographic fingerprint of this certificate. Any modification changes the hash.
                  </div>

                  <div className="divider" />

                  <div className="section-title">Blockchain Record</div>
                  <div className="chain-status-row">
                    <span style={{ fontSize: 20 }}>🔗</span>
                    <span className="chain-status-text" style={{
                      color: result.blockchain_status === "RECORDED" ? "var(--green)" : "var(--amber)"
                    }}>
                      {result.blockchain_status ?? "PENDING"}
                    </span>
                    <span className="badge" style={{ background: "#0e1e30", color: "#60a5fa", border: "1px solid #1e3a5f", fontSize: 10 }}>
                      PROTOTYPE CHAIN
                    </span>
                  </div>
                  {result.blockchain_tx && (
                    <>
                      <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4, marginTop: 8 }}>Block Hash (TX)</div>
                      <div className="hash-box" style={{ fontSize: 11 }}>{result.blockchain_tx}</div>
                    </>
                  )}
                  <button className="btn btn-outline" style={{ marginTop: 14, width: "100%" }} onClick={onViewCert}>
                    View Full Certificate →
                  </button>
                </div>
              )}

              <div className="cato-note card">
                <div style={{ fontSize: 12, fontWeight: 700, color: "var(--accent)", marginBottom: 6 }}>How CATO works</div>
                <div style={{ fontSize: 11, color: "var(--text-muted)", lineHeight: 1.6 }}>
                  CATO <strong style={{ color: "var(--text-dim)" }}>orchestrates</strong> security tools — it doesn't replace them.
                  Scanners produce evidence → CATO normalizes it → Policy evaluates it → Decision is produced → Certificate is issued → Hash is blockchain-recorded.
                </div>
              </div>
            </div>
          </div>
        </>
      )}

      {/* ── Empty state ── */}
      {!result && !loading && !showSelector && (
        <div className="empty-state">
          <img src="/cato-logo.png" alt="CATO" className="empty-logo" />
          <div className="empty-title">Ready to analyze</div>
          <button className="btn btn-primary" onClick={() => setShowSelector(true)}>Select a Project</button>
        </div>
      )}
    </div>
  );
}
