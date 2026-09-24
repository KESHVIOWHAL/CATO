import { useState } from "react";
import { getPreAITiming, getPostAITiming } from "../api.ts";
import type { PreAITiming, PostAITiming } from "../api.ts";
import "./TimingView.css";

function Bar({ ms, maxMs, color = "var(--accent)" }: { ms: number; maxMs: number; color?: string }) {
  const pct = maxMs > 0 ? Math.max(3, (ms / maxMs) * 100) : 3;
  return (
    <div className="t-bar-wrap">
      <div className="t-bar" style={{ width: `${pct}%`, background: color }} />
    </div>
  );
}

function StageTable({ stages, title }: { stages: Record<string, number>; title?: string }) {
  const maxMs = Math.max(...Object.values(stages), 0.1);
  return (
    <div className="stage-table">
      {title && <div className="st-title">{title}</div>}
      {Object.entries(stages).map(([stage, ms]) => (
        <div key={stage} className="stage-row">
          <div className="stage-name">{stage}</div>
          <Bar ms={ms} maxMs={maxMs} />
          <div className="stage-ms">{ms} ms</div>
        </div>
      ))}
    </div>
  );
}

export default function TimingView() {
  const [preData,  setPreData]  = useState<PreAITiming  | null>(null);
  const [postData, setPostData] = useState<PostAITiming | null>(null);
  const [preLoad,  setPreLoad]  = useState(false);
  const [postLoad, setPostLoad] = useState(false);
  const [preError,  setPreError]  = useState<string | null>(null);
  const [postError, setPostError] = useState<string | null>(null);

  async function handlePreAI() {
    setPreLoad(true); setPreError(null);
    try { setPreData(await getPreAITiming()); }
    catch (e: unknown) { setPreError(e instanceof Error ? e.message : "Failed"); }
    finally { setPreLoad(false); }
  }

  async function handlePostAI() {
    setPostLoad(true); setPostError(null);
    try { setPostData(await getPostAITiming()); }
    catch (e: unknown) { setPostError(e instanceof Error ? e.message : "Failed"); }
    finally { setPostLoad(false); }
  }

  const DECISION_COLOR: Record<string, string> = {
    BLOCK:   "var(--red)",
    REVIEW:  "var(--amber)",
    APPROVE: "var(--green)",
  };

  return (
    <div className="timing-wrap">
      <div style={{ marginBottom: 24 }}>
        <h2 style={{ fontSize: 22, fontWeight: 800, marginBottom: 6 }}>CATO Timing — Before &amp; After AI</h2>
        <p style={{ fontSize: 13, color: "var(--text-muted)", maxWidth: 640, lineHeight: 1.6 }}>
          CATO operates in two layers. Click each button to run the actual pipeline and see real measured times.
          No values are hardcoded.
        </p>
      </div>

      {/* Architecture overview */}
      <div className="timing-arch card">
        <div className="ta-flow">
          <div className="ta-box ta-dev">
            <div className="ta-label">Developer</div>
            <div className="ta-sub">writes prompt</div>
          </div>
          <div className="ta-arrow">→</div>
          <div className="ta-box ta-pre">
            <div className="ta-label">CATO Pre-AI</div>
            <div className="ta-sub">inspect · sanitize · route</div>
            <div className="ta-badge">milliseconds</div>
          </div>
          <div className="ta-arrow">→</div>
          <div className="ta-box ta-ai">
            <div className="ta-label">AI Model</div>
            <div className="ta-sub">Claude / GPT / Gemini</div>
          </div>
          <div className="ta-arrow">→</div>
          <div className="ta-box ta-post">
            <div className="ta-label">CATO Post-AI</div>
            <div className="ta-sub">6 security checks</div>
            <div className="ta-badge">seconds</div>
          </div>
          <div className="ta-arrow">→</div>
          <div className="ta-box ta-cert">
            <div className="ta-label">Trust Decision</div>
            <div className="ta-sub">certificate · blockchain</div>
          </div>
        </div>
      </div>

      <div className="timing-split">

        {/* ── PRE-AI ── */}
        <div>
          <div className="timing-section-header">
            <div>
              <div className="ts-title">⚡ PRE-AI Layer</div>
              <div className="ts-sub">Prompt inspection pipeline — runs BEFORE the AI model receives input</div>
            </div>
            <button className="btn btn-primary" onClick={handlePreAI} disabled={preLoad}>
              {preLoad ? <><span className="spinner" /> Measuring…</> : "Measure Pre-AI Time"}
            </button>
          </div>

          {preError && <div className="error-msg" style={{ marginTop: 8 }}>⚠ {preError}</div>}

          {preData && (
            <div className="timing-results">
              <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 14, lineHeight: 1.6 }}>
                {preData.description}<br />
                <strong>10 runs each</strong> — all values from <code>time.perf_counter()</code>.
              </div>

              {Object.entries(preData.results).map(([size, r]) => (
                <div key={size} className="card timing-card">
                  <div className="tc-header">
                    <span className="tc-size">{size.toUpperCase()} PROMPT</span>
                    <span className="tc-kb">{r.prompt_size_kb} KB</span>
                  </div>

                  <div className="tc-stats">
                    {[
                      { label: "Average",  val: r.avg_ms,    color: "var(--accent)" },
                      { label: "Median",   val: r.median_ms, color: "var(--accent)" },
                      { label: "Min",      val: r.min_ms,    color: "var(--green)" },
                      { label: "Max",      val: r.max_ms,    color: "var(--red)" },
                    ].map(s => (
                      <div key={s.label} className="tc-stat">
                        <div className="tc-stat-val" style={{ color: s.color }}>{s.val} ms</div>
                        <div className="tc-stat-label">{s.label}</div>
                      </div>
                    ))}
                  </div>

                  <StageTable stages={r.stage_avg_ms} title="Per-stage averages" />
                </div>
              ))}

              <div className="timing-note">
                Pre-AI protection is designed to remain lightweight.
                Heavier software verification occurs after generation and may take seconds or longer.
              </div>
            </div>
          )}
        </div>

        {/* ── POST-AI ── */}
        <div>
          <div className="timing-section-header">
            <div>
              <div className="ts-title">🔬 POST-AI Layer</div>
              <div className="ts-sub">Software verification pipeline — runs AFTER AI generates code</div>
            </div>
            <button className="btn btn-primary" onClick={handlePostAI} disabled={postLoad}>
              {postLoad ? <><span className="spinner" /> Measuring…</> : "Measure Post-AI Time"}
            </button>
          </div>

          {postError && <div className="error-msg" style={{ marginTop: 8 }}>⚠ {postError}</div>}

          {postData && (
            <div className="timing-results">
              <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 14, lineHeight: 1.6 }}>
                {postData.description}<br />
                <em>{postData.note}</em>
              </div>

              {postData.results.map((r, i) => r.error ? null : (
                <div key={i} className="card timing-card">
                  <div className="tc-header">
                    <span className="tc-size">{r.project.replace(/_/g, " ").toUpperCase()}</span>
                    <span className="tc-kb">{r.files_scanned} files</span>
                    <span style={{ marginLeft: "auto", fontWeight: 800, color: DECISION_COLOR[r.decision] }}>
                      {r.decision}
                    </span>
                  </div>

                  <div className="tc-stats">
                    <div className="tc-stat">
                      <div className="tc-stat-val" style={{ color: "var(--accent)", fontSize: 24 }}>
                        {r.total_s}s
                      </div>
                      <div className="tc-stat-label">Total</div>
                    </div>
                    <div className="tc-stat">
                      <div className="tc-stat-val" style={{ color: "var(--text-dim)" }}>
                        {r.total_ms} ms
                      </div>
                      <div className="tc-stat-label">Milliseconds</div>
                    </div>
                  </div>

                  <StageTable stages={r.stage_ms} />
                </div>
              ))}

              <div className="timing-note">
                Post-AI timing is dominated by network I/O (OSV.dev CVE lookups) and pytest execution.
                For larger projects with many files, this scales roughly linearly with file count.
                Can be run asynchronously or at the CI/CD checkpoint.
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Summary table — shown when both are loaded */}
      {preData && postData && (
        <div className="card" style={{ marginTop: 20 }}>
          <div className="section-title">Summary — CATO Overhead</div>
          <table className="compare-table" style={{ marginTop: 8 }}>
            <thead>
              <tr>
                <th>Layer</th>
                <th>When</th>
                <th>What runs</th>
                <th>Typical time</th>
                <th>Scales with</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td style={{ fontWeight: 700, color: "var(--accent)" }}>Pre-AI</td>
                <td>Before prompt reaches AI</td>
                <td>Secret · PII · Injection · Policy checks</td>
                <td style={{ fontWeight: 700, color: "var(--green)" }}>
                  {preData.results["medium"]?.avg_ms ?? "—"} ms avg
                </td>
                <td>Prompt size (sub-linear)</td>
              </tr>
              <tr>
                <td style={{ fontWeight: 700, color: "var(--accent)" }}>Post-AI</td>
                <td>After AI generates code</td>
                <td>6 scanners · SAST · Deps · Tests · Decision</td>
                <td style={{ fontWeight: 700, color: "var(--amber)" }}>
                  {postData.results[0]?.total_s ?? "—"}s per project
                </td>
                <td>File count · Dep count · Test count</td>
              </tr>
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
