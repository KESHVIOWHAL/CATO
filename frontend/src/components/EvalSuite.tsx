import { useState } from "react";
import { runEvaluationSuite, analyzeProject } from "../api.ts";
import type { EvalResult } from "../api.ts";
import "./EvalSuite.css";

const PROJECT_META: Record<string, { desc: string; expected: string; icon: string }> = {
  ecommerce_app: {
    icon: "🛒",
    desc: "Multi-file Flask e-commerce app with SQL injection, hardcoded payment API keys, and vulnerable dependencies",
    expected: "BLOCK",
  },
  clean_api: {
    icon: "✅",
    desc: "Secure REST API with parameterized queries, env-based secrets, and clean dependencies",
    expected: "APPROVE",
  },
  medium_risk: {
    icon: "⚠",
    desc: "Application with medium-severity findings: weak hash, unsafe assert — no critical secrets",
    expected: "REVIEW",
  },
  complex_app: {
    icon: "🏗",
    desc: "Multi-module app (auth, database, API, services, models, utils) with real vulnerabilities across 8 files",
    expected: "BLOCK",
  },
};

const DECISION_COLOR: Record<string, string> = {
  BLOCK:   "var(--red)",
  REVIEW:  "var(--amber)",
  APPROVE: "var(--green)",
};

const DECISION_BG: Record<string, string> = {
  BLOCK:   "var(--red-bg)",
  REVIEW:  "var(--amber-bg)",
  APPROVE: "var(--green-bg)",
};

export default function EvalSuite() {
  const [results, setResults]   = useState<EvalResult[]>([]);
  const [loading, setLoading]   = useState(false);
  const [running, setRunning]   = useState<string | null>(null);
  const [error, setError]       = useState<string | null>(null);
  const [singleResults, setSingleResults] = useState<Record<string, EvalResult>>({});

  async function handleRunAll() {
    setLoading(true);
    setError(null);
    setResults([]);
    try {
      const r = await runEvaluationSuite();
      setResults(r.results);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Evaluation failed");
    } finally {
      setLoading(false);
    }
  }

  async function handleRunSingle(projectId: string, projectName: string) {
    setRunning(projectId);
    try {
      const r = await analyzeProject(projectName, projectId);
      setSingleResults(prev => ({
        ...prev,
        [projectId]: {
          id:          projectId,
          name:        projectName,
          files:       r.files_scanned,
          findings:    r.checks.reduce((n, c) => n + c.findings.length, 0),
          critical:    r.checks.reduce((n, c) => n + c.findings.filter(f => f.severity === "CRITICAL").length, 0),
          high:        r.checks.reduce((n, c) => n + c.findings.filter(f => f.severity === "HIGH").length, 0),
          medium:      r.checks.reduce((n, c) => n + c.findings.filter(f => f.severity === "MEDIUM").length, 0),
          tests:       r.checks.find(c => c.check_name.includes("Test"))?.status ?? "SKIP",
          decision:    r.decision,
          trust_score: r.trust_score,
          elapsed_s:   0,
          cert_id:     r.certificate_id,
        } as EvalResult,
      }));
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Analysis failed");
    } finally {
      setRunning(null);
    }
  }

  const displayResults = results.length > 0 ? results :
    Object.values(singleResults).length > 0 ? Object.values(singleResults) : [];

  return (
    <div className="eval-wrap">
      {/* Header */}
      <div className="eval-header card">
        <div>
          <h2 style={{ fontSize: 22, fontWeight: 800, marginBottom: 4 }}>CATO Evaluation Suite</h2>
          <p style={{ fontSize: 13, color: "var(--text-muted)" }}>
            Test CATO across 4 different projects — simple to complex. All results generated from real analysis.
          </p>
        </div>
        <button className="btn btn-primary" onClick={handleRunAll} disabled={loading}>
          {loading
            ? <><span className="spinner" /> Running all projects…</>
            : "▶  Run All 4 Projects"}
        </button>
      </div>

      {error && <div className="error-msg" style={{ marginTop: 12 }}>⚠ {error}</div>}

      {/* Project cards */}
      <div className="eval-projects">
        {Object.entries(PROJECT_META).map(([id, meta]) => {
          const res = singleResults[id] || results.find(r => r.id === id);
          const isRunning = running === id;

          return (
            <div key={id} className="eval-project-card card">
              <div className="epc-header">
                <span className="epc-icon">{meta.icon}</span>
                <div className="epc-info">
                  <div className="epc-name">{id.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase())}</div>
                  <div className="epc-desc">{meta.desc}</div>
                </div>
                <div className="epc-expected">
                  Expected:
                  <span style={{ color: DECISION_COLOR[meta.expected], fontWeight: 700, marginLeft: 4 }}>
                    {meta.expected}
                  </span>
                </div>
              </div>

              {/* Result row */}
              {res && !res.error && (
                <div className="epc-result" style={{ background: DECISION_BG[res.decision] || "var(--surface2)" }}>
                  <div className="epc-result-decision" style={{ color: DECISION_COLOR[res.decision] }}>
                    {res.decision}
                  </div>
                  <div className="epc-result-stats">
                    <span>Score: <strong>{res.trust_score}</strong>/100</span>
                    <span>Files: <strong>{res.files}</strong></span>
                    <span>Findings: <strong>{res.findings}</strong></span>
                    {res.critical > 0 && <span style={{ color: "var(--red)" }}>CRIT: <strong>{res.critical}</strong></span>}
                    {res.high > 0     && <span style={{ color: "#c47d0e" }}>HIGH: <strong>{res.high}</strong></span>}
                    {res.medium > 0   && <span style={{ color: "var(--amber)" }}>MED: <strong>{res.medium}</strong></span>}
                    <span>Tests: <strong style={{ color: res.tests === "PASS" ? "var(--green)" : "var(--red)" }}>{res.tests}</strong></span>
                    {res.elapsed_s > 0 && <span>Time: <strong>{res.elapsed_s}s</strong></span>}
                  </div>
                  {res.decision === meta.expected
                    ? <span style={{ color: "var(--green)", fontSize: 12, fontWeight: 700 }}>✓ Matches expected</span>
                    : <span style={{ color: "var(--amber)", fontSize: 12 }}>⚠ Differs from expected — evidence-driven</span>
                  }
                </div>
              )}
              {res?.error && (
                <div className="error-msg" style={{ marginTop: 8 }}>{res.error}</div>
              )}

              <button
                className="btn btn-outline"
                style={{ marginTop: 12, width: "100%", fontSize: 13 }}
                onClick={() => handleRunSingle(id, id.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase()))}
                disabled={isRunning || loading}
              >
                {isRunning
                  ? <><span className="spinner" /> Analyzing…</>
                  : res ? "↻  Re-run CATO Analysis" : "⬡  Run CATO Analysis"}
              </button>
            </div>
          );
        })}
      </div>

      {/* Summary table */}
      {displayResults.length > 0 && (
        <div className="card" style={{ marginTop: 20 }}>
          <div className="section-title" style={{ marginBottom: 12 }}>
            Evaluation Results
            <span style={{ fontWeight: 400, marginLeft: 8, color: "var(--text-muted)" }}>
              — all values from actual CATO analysis
            </span>
          </div>
          <div style={{ overflowX: "auto" }}>
            <table className="eval-table">
              <thead>
                <tr>
                  <th>Project</th>
                  <th>Files</th>
                  <th>Findings</th>
                  <th>Critical</th>
                  <th>High</th>
                  <th>Medium</th>
                  <th>Tests</th>
                  <th>Score</th>
                  <th>Decision</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {displayResults.map((r, i) => (
                  <tr key={i}>
                    <td style={{ fontWeight: 700 }}>{r.name || r.id}</td>
                    <td>{r.files}</td>
                    <td style={{ fontWeight: 700 }}>{r.findings}</td>
                    <td style={{ color: r.critical > 0 ? "var(--red)" : "var(--text-muted)", fontWeight: r.critical > 0 ? 700 : 400 }}>{r.critical}</td>
                    <td style={{ color: r.high > 0 ? "#c47d0e" : "var(--text-muted)", fontWeight: r.high > 0 ? 700 : 400 }}>{r.high}</td>
                    <td style={{ color: r.medium > 0 ? "var(--amber)" : "var(--text-muted)" }}>{r.medium}</td>
                    <td>
                      <span className={`badge ${r.tests === "PASS" ? "badge-pass" : r.tests === "FAIL" ? "badge-fail" : "badge-skip"}`} style={{ fontSize: 10 }}>
                        {r.tests}
                      </span>
                    </td>
                    <td style={{ fontWeight: 700, color: DECISION_COLOR[r.decision] }}>{r.trust_score}</td>
                    <td>
                      <span style={{
                        fontWeight: 800, fontSize: 13,
                        color: DECISION_COLOR[r.decision] || "var(--text)"
                      }}>
                        {r.decision}
                      </span>
                    </td>
                    <td style={{ color: "var(--text-muted)", fontSize: 12 }}>
                      {r.elapsed_s > 0 ? `${r.elapsed_s}s` : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 10 }}>
            All values generated by real CATO scanners. Decisions are evidence-driven — not based on project name.
          </div>
        </div>
      )}
    </div>
  );
}
