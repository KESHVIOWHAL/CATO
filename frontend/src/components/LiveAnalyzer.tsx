import { useState } from "react";
import { analyzeInline } from "../api.ts";
import type { InlineResult, WorkflowStep, InlineFinding } from "../api.ts";
import "./LiveAnalyzer.css";

const DEMO_CODE = `# AI-generated payment service — paste your own code below
import subprocess
import sqlite3

# Hardcoded credentials (security issue)
API_KEY = "sk-demo-hardcoded-9F82X71abcdef"
DB_PASSWORD = "admin123"

def get_user(username: str):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SQL Injection vulnerability
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()

def run_command(user_input: str):
    # Command injection via shell=True
    subprocess.run(user_input, shell=True)

def add(a, b):
    return a + b
`;

const DEMO_REQS = `flask==0.12.2
requests==2.18.0
pyyaml==3.12`;

const STEP_ORDER = [
  "Requirement & Intent",
  "Architecture & Policy",
  "Secret Detection",
  "Dependency Analysis",
  "Static Analysis (SAST)",
  "Functional Tests",
];

// ── Animated workflow pipeline ─────────────────────────────────────────────
function WorkflowPipeline({ steps, running, activeIdx }: {
  steps: WorkflowStep[];
  running: boolean;
  activeIdx: number;
}) {
  return (
    <div className="wf-pipeline">
      {STEP_ORDER.map((name, i) => {
        const step = steps.find(s => s.name === name);
        const isActive  = running && i === activeIdx;
        const isDone    = step !== undefined;
        const isFail    = step?.status === "FAIL";
        const isPass    = step?.status === "PASS";
        const isPending = !isDone && !isActive;

        return (
          <div key={name} className="wf-step-wrap">
            <div className={`wf-step ${isActive ? "wf-active" : isDone ? (isFail ? "wf-fail" : "wf-pass") : "wf-pending"}`}>
              <div className="wf-step-icon">
                {isActive ? <span className="spinner" style={{ width: 14, height: 14, borderTopColor: "var(--accent)" }} /> :
                 isDone   ? (isFail ? "✗" : "✓") : "·"}
              </div>
              <div className="wf-step-body">
                <div className="wf-step-name">{name}</div>
                {step && (
                  <>
                    <div className="wf-step-summary">{step.summary}</div>
                    <div className="wf-step-meta">
                      {step.findings > 0 && <span className="wf-findings-count">{step.findings} finding{step.findings !== 1 ? "s" : ""}</span>}
                      <span className="wf-ms">{step.ms} ms</span>
                    </div>
                  </>
                )}
              </div>
              <div className="wf-step-status">
                {isActive && <span style={{ fontSize: 11, color: "var(--accent)" }}>scanning…</span>}
                {isDone && <span className={`badge ${isFail ? "badge-fail" : isPass ? "badge-pass" : "badge-skip"}`} style={{ fontSize: 10 }}>
                  {isFail ? "FAIL" : "PASS"}
                </span>}
                {isPending && <span style={{ fontSize: 11, color: "var(--border)" }}>pending</span>}
              </div>
            </div>
            {i < STEP_ORDER.length - 1 && (
              <div className={`wf-arrow ${isDone ? "wf-arrow-done" : ""}`}>↓</div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ── Finding card ───────────────────────────────────────────────────────────
function FindingCard({ f, idx }: { f: InlineFinding; idx: number }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={`finding-card fc-${f.severity.toLowerCase()}`}>
      <div className="finding-card-header" onClick={() => setOpen(!open)}>
        <span className="fc-num">#{idx + 1}</span>
        <span className={`sev-badge sev-${f.severity.toLowerCase()}`}>{f.severity}</span>
        <span className="fc-title">{f.title}</span>
        <span style={{ fontSize: 11, color: "var(--text-muted)", marginLeft: "auto", flexShrink: 0 }}>{f.check}</span>
        <span style={{ color: "var(--text-muted)", marginLeft: 8, fontSize: 12 }}>{open ? "▲" : "▼"}</span>
      </div>
      {open && (
        <div className="finding-card-body">
          <div className="fc-desc">{f.description}</div>
          {f.location && <div className="fc-loc">📍 {f.location}</div>}
          {f.remediation && (
            <div className="fc-fix">
              <div className="fc-fix-label">How to fix</div>
              <pre className="fc-fix-pre">{f.remediation}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Decision banner ────────────────────────────────────────────────────────
function DecisionBanner({ result }: { result: InlineResult }) {
  const color =
    result.decision === "BLOCK"   ? "var(--red)"   :
    result.decision === "REVIEW"  ? "var(--amber)" : "var(--green)";
  const cls =
    result.decision === "BLOCK"   ? "decision-block"  :
    result.decision === "REVIEW"  ? "decision-review" : "decision-approve";
  const circumference = 2 * Math.PI * 28;
  const offset = circumference - (result.trust_score / 100) * circumference;

  return (
    <div className={`card live-decision ${cls}`}>
      <div className="live-decision-inner">
        <div>
          <div className="section-title">CATO TRUST DECISION</div>
          <div className="live-decision-word" style={{ color }}>{result.decision}</div>
          <div style={{ fontWeight: 700, color, marginTop: 4 }}>{result.risk_level}</div>
          <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 4 }}>
            {result.lines_scanned} lines · {result.all_findings.length} finding{result.all_findings.length !== 1 ? "s" : ""} · 6 checks
          </div>
          {result.decision === "BLOCK" && (
            <div className="block-notice" style={{ marginTop: 8 }}>🚫 STOP — does not meet trust requirements</div>
          )}
          {result.decision === "REVIEW" && (
            <div className="review-notice" style={{ marginTop: 8 }}>⚠ REVIEW — human approval required</div>
          )}
        </div>

        <svg width="80" height="80" viewBox="0 0 80 80">
          <circle cx="40" cy="40" r="28" fill="none" stroke="var(--border)" strokeWidth="6" />
          <circle cx="40" cy="40" r="28" fill="none"
            stroke={color} strokeWidth="6"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            transform="rotate(-90 40 40)"
            style={{ transition: "stroke-dashoffset 0.8s ease" }}
          />
          <text x="40" y="37" textAnchor="middle" fill={color} fontSize="16" fontWeight="800">
            {result.trust_score}
          </text>
          <text x="40" y="50" textAnchor="middle" fill="var(--text-muted)" fontSize="8">/100</text>
        </svg>
      </div>

      <div className="live-reasons">
        {result.decision_reasons.slice(0, 5).map((r, i) => {
          const isCrit  = r.startsWith("[CRITICAL]");
          const isHigh  = r.startsWith("[HIGH]");
          const isArrow = r.startsWith("→");
          return (
            <div key={i} className="live-reason">
              <span style={{ color: isCrit ? "var(--red)" : isHigh ? "#c47d0e" : isArrow ? color : "var(--accent)", fontWeight: 700 }}>
                {isArrow ? "→" : "•"}
              </span>
              <span style={{ color: isArrow ? color : "var(--text-dim)", fontWeight: isArrow ? 700 : 400 }}>
                {r.replace(/^→\s*/, "")}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Main component ──────────────────────────────────────────────────────────
export default function LiveAnalyzer() {
  const [code, setCode]         = useState(DEMO_CODE);
  const [reqs, setReqs]         = useState(DEMO_REQS);
  const [context, setContext]   = useState("");
  const [filename, setFilename] = useState("pasted_code.py");
  const [showReqs, setShowReqs] = useState(false);
  const [showCtx, setShowCtx]   = useState(false);

  const [running, setRunning]     = useState(false);
  const [activeIdx, setActiveIdx] = useState(-1);
  const [steps, setSteps]         = useState<WorkflowStep[]>([]);
  const [result, setResult]       = useState<InlineResult | null>(null);
  const [error, setError]         = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"findings" | "recs" | "provenance">("findings");

  async function handleAnalyze() {
    if (!code.trim()) return;
    setRunning(true);
    setSteps([]);
    setResult(null);
    setError(null);
    setActiveIdx(0);

    // Animate steps while backend runs
    let stepI = 0;
    const interval = setInterval(() => {
      stepI++;
      setActiveIdx(Math.min(stepI, STEP_ORDER.length - 1));
    }, 500);

    try {
      const r = await analyzeInline({
        code,
        filename,
        requirements: reqs,
        context,
      });
      clearInterval(interval);
      setSteps(r.workflow_steps);
      setActiveIdx(-1);
      setResult(r);
    } catch (e: unknown) {
      clearInterval(interval);
      setError(e instanceof Error ? e.message : "Analysis failed — is backend running?");
    } finally {
      setRunning(false);
    }
  }

  function handleLoadDemo() {
    setCode(DEMO_CODE);
    setReqs(DEMO_REQS);
    setResult(null);
    setSteps([]);
  }

  const totalMs = steps.reduce((s, x) => s + x.ms, 0);

  return (
    <div className="live-wrap">
      {/* Header */}
      <div className="live-header card">
        <div>
          <h2 style={{ fontSize: 22, fontWeight: 800, marginBottom: 4 }}>Paste Code → CATO Analysis</h2>
          <p style={{ fontSize: 13, color: "var(--text-muted)" }}>
            Paste any Python code. CATO runs the complete 6-scanner workflow in real time and shows you every step.
          </p>
        </div>
        <button className="btn btn-outline" style={{ alignSelf: "flex-start" }} onClick={handleLoadDemo}>
          Load Demo Code
        </button>
      </div>

      <div className="live-layout">
        {/* LEFT — Input */}
        <div className="live-input-col">
          <div className="card">
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
              <div className="section-title" style={{ margin: 0 }}>Source Code</div>
              <input
                className="filename-input"
                value={filename}
                onChange={e => setFilename(e.target.value)}
                placeholder="filename.py"
              />
              <div style={{ marginLeft: "auto", fontSize: 12, color: "var(--text-muted)" }}>
                {code.split("\n").length} lines
              </div>
            </div>
            <textarea
              className="code-input"
              value={code}
              onChange={e => setCode(e.target.value)}
              spellCheck={false}
              rows={18}
            />

            {/* Optional requirements */}
            <button className="toggle-btn" onClick={() => setShowReqs(!showReqs)}>
              {showReqs ? "▲" : "▼"} requirements.txt {showReqs ? "" : "(optional)"}
            </button>
            {showReqs && (
              <textarea
                className="code-input"
                style={{ marginTop: 8, fontFamily: "monospace", fontSize: 12 }}
                rows={4}
                placeholder={"flask==0.12.2\nrequests==2.18.0"}
                value={reqs}
                onChange={e => setReqs(e.target.value)}
              />
            )}

            {/* Context notes */}
            <button className="toggle-btn" onClick={() => setShowCtx(!showCtx)}>
              {showCtx ? "▲" : "▼"} Architecture context {showCtx ? "" : "(optional)"}
            </button>
            {showCtx && (
              <textarea
                className="code-input"
                style={{ marginTop: 8, fontSize: 13 }}
                rows={3}
                placeholder="e.g. Public API handling payments and PII. All secrets must use env vars."
                value={context}
                onChange={e => setContext(e.target.value)}
              />
            )}

            <button
              className="btn btn-primary"
              style={{ width: "100%", marginTop: 14, fontSize: 15 }}
              onClick={handleAnalyze}
              disabled={running || !code.trim()}
            >
              {running
                ? <><span className="spinner" /> Running CATO Analysis…</>
                : "⬡  Run CATO Analysis"}
            </button>
            {error && <div className="error-msg" style={{ marginTop: 10 }}>⚠ {error}</div>}
          </div>
        </div>

        {/* RIGHT — Workflow + Results */}
        <div className="live-result-col">
          {/* Workflow pipeline */}
          <div className="card">
            <div className="section-title">
              CATO Workflow
              {totalMs > 0 && (
                <span style={{ fontWeight: 400, marginLeft: 8, color: "var(--text-muted)" }}>
                  total: {totalMs.toFixed(1)} ms
                </span>
              )}
            </div>
            <WorkflowPipeline steps={steps} running={running} activeIdx={activeIdx} />
          </div>

          {/* Decision */}
          {result && (
            <>
              <DecisionBanner result={result} />

              {/* Tabs: Findings / Recommendations / Provenance */}
              <div className="card" style={{ marginTop: 14 }}>
                <div className="result-tabs">
                  {(["findings", "recs", "provenance"] as const).map(tab => (
                    <button
                      key={tab}
                      className={`result-tab ${activeTab === tab ? "result-tab-active" : ""}`}
                      onClick={() => setActiveTab(tab)}
                    >
                      {tab === "findings"   ? `Findings (${result.all_findings.length})` :
                       tab === "recs"       ? `Fix It (${result.recommendations.length})` :
                       "Provenance Chain"}
                    </button>
                  ))}
                </div>

                {/* Findings tab */}
                {activeTab === "findings" && (
                  <div className="tab-body">
                    {result.all_findings.length === 0 ? (
                      <div style={{ color: "var(--green)", fontWeight: 600, padding: "12px 0" }}>
                        ✓ No security findings detected
                      </div>
                    ) : (
                      result.all_findings.map((f, i) => <FindingCard key={i} f={f} idx={i} />)
                    )}
                  </div>
                )}

                {/* Fix It tab */}
                {activeTab === "recs" && (
                  <div className="tab-body">
                    {result.recommendations.length === 0 ? (
                      <div style={{ color: "var(--green)", fontWeight: 600, padding: "12px 0" }}>
                        ✓ No recommendations — code looks clean
                      </div>
                    ) : (
                      result.recommendations.map((r, i) => (
                        <div key={i} className={`rec-item rec-${r.severity.toLowerCase()}`}>
                          <div className="rec-header" style={{ cursor: "default" }}>
                            <span className="rec-num">#{r.priority}</span>
                            <span className="rec-icon">
                              {r.category === "SECRET" ? "🔑" : r.category === "SAST" ? "🔬" : r.category === "DEPENDENCY" ? "📦" : "🧪"}
                            </span>
                            <div className="rec-title-block">
                              <span className="rec-title">{r.title}</span>
                              {r.location && <span className="rec-loc">📍 {r.location}</span>}
                            </div>
                            <span className={`sev-badge sev-${r.severity.toLowerCase()}`} style={{ marginLeft: "auto" }}>
                              {r.severity}
                            </span>
                          </div>
                          <div className="rec-body">
                            <div className="rec-section">
                              <div className="rec-section-label">Problem</div>
                              <div className="rec-section-text">{r.what}</div>
                            </div>
                            <div className="rec-section">
                              <div className="rec-section-label">Fix</div>
                              <pre className="rec-fix">{r.fix}</pre>
                            </div>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                )}

                {/* Provenance tab */}
                {activeTab === "provenance" && (
                  <div className="tab-body">
                    <div className="prov-chain" style={{ flexDirection: "column", gap: 6 }}>
                      {result.provenance.nodes.map((node, i) => (
                        <div key={i} className={`prov-row ${node.status === "FAIL" ? "prow-fail" : node.status === "PASS" ? "prow-pass" : "prow-pending"}`}>
                          <span className="prow-stage">{node.stage}</span>
                          <span className={`badge ${node.status === "PASS" ? "badge-pass" : node.status === "FAIL" ? "badge-fail" : "badge-skip"}`} style={{ fontSize: 10 }}>
                            {node.status}
                          </span>
                          <span className="prow-summary">{node.summary}</span>
                          {node.findings_count > 0 && (
                            <span style={{ fontSize: 11, color: "var(--red)", fontWeight: 700, marginLeft: "auto" }}>
                              {node.findings_count} issue{node.findings_count !== 1 ? "s" : ""}
                            </span>
                          )}
                        </div>
                      ))}
                    </div>
                    <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 10 }}>
                      {result.provenance.traceable
                        ? "✓ Evidence chain is traceable from requirements to runtime"
                        : "✗ Evidence chain has breaks — one or more stages failed"}
                    </div>
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
