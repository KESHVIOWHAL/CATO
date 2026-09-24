import { useState, useEffect } from "react";
import { compareAIvsCato, runBenchmark, runSizeBenchmark, getDemoPrompt } from "../api.ts";
import type { CompareResult, BenchmarkResult } from "../api.ts";
import "./AIvsCATO.css";

const AI_MODELS = [
  { id: "claude",     label: "Claude (Anthropic)" },
  { id: "gpt",        label: "GPT-4 (OpenAI)" },
  { id: "gemini",     label: "Gemini (Google)" },
  { id: "local",      label: "Local AI (On-Prem)" },
  { id: "enterprise", label: "Enterprise AI (Private)" },
];

const ACTION_COLOR: Record<string, string> = {
  BLOCKED:   "var(--red)",
  SANITIZED: "var(--amber)",
  APPROVED:  "var(--green)",
  SEND_AS_IS:"var(--red)",
};

// ── Bar chart for latency stages ─────────────────────────────────────────────
function LatencyBar({ label, ms, maxMs }: { label: string; ms: number; maxMs: number }) {
  const pct = maxMs > 0 ? Math.max(4, (ms / maxMs) * 100) : 4;
  return (
    <div className="lat-row">
      <div className="lat-label">{label}</div>
      <div className="lat-bar-wrap">
        <div className="lat-bar" style={{ width: `${pct}%` }} />
      </div>
      <div className="lat-ms">{ms} ms</div>
    </div>
  );
}

// ── Mini sparkline for benchmark runs ────────────────────────────────────────
function Sparkline({ data }: { data: number[] }) {
  if (data.length < 2) return null;
  const max = Math.max(...data);
  const min = Math.min(...data);
  const range = max - min || 1;
  const w = 200, h = 40;
  const pts = data.map((v, i) => {
    const x = (i / (data.length - 1)) * w;
    const y = h - ((v - min) / range) * (h - 4) - 2;
    return `${x},${y}`;
  }).join(" ");
  return (
    <svg width={w} height={h} className="sparkline">
      <polyline fill="none" stroke="var(--accent)" strokeWidth="1.5" points={pts} />
    </svg>
  );
}

export default function AIvsCATO() {
  const [prompt, setPrompt]       = useState("");
  const [model, setModel]         = useState("claude");
  const [result, setResult]       = useState<CompareResult | null>(null);
  const [loading, setLoading]     = useState(false);
  const [error, setError]         = useState<string | null>(null);

  // Benchmark state
  const [benchRuns, setBenchRuns]         = useState(20);
  const [benchResult, setBenchResult]     = useState<BenchmarkResult | null>(null);
  const [sizeResults, setSizeResults]     = useState<Record<string, BenchmarkResult> | null>(null);
  const [benchLoading, setBenchLoading]   = useState(false);
  const [sizeLoading, setSizeLoading]     = useState(false);

  // Proof-of-value stats
  const [povStats, setPovStats] = useState({ secrets: 0, blocked: 0, sanitized: 0 });

  useEffect(() => {
    getDemoPrompt().then(d => setPrompt(d.prompt)).catch(() => {});
  }, []);

  async function handleCompare() {
    if (!prompt.trim()) return;
    setLoading(true); setError(null);
    try {
      const r = await compareAIvsCato(prompt, model);
      setResult(r);
      // Update PoV stats from findings
      const sanitized = r.cato.findings.filter(f => f.action === "SANITIZE").length;
      setPovStats(prev => ({
        secrets: prev.secrets + r.cato.findings.filter(f => f.category === "SECRET_CREDENTIAL").length,
        blocked: prev.blocked + (r.cato.action === "BLOCKED" ? 1 : 0),
        sanitized: prev.sanitized + sanitized,
      }));
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Request failed");
    } finally {
      setLoading(false);
    }
  }

  async function handleBenchmark() {
    setBenchLoading(true);
    try {
      const r = await runBenchmark(prompt || "test prompt", benchRuns);
      setBenchResult(r);
    } finally {
      setBenchLoading(false);
    }
  }

  async function handleSizeBenchmark() {
    setSizeLoading(true);
    try {
      const r = await runSizeBenchmark();
      setSizeResults(r);
    } finally {
      setSizeLoading(false);
    }
  }

  const maxStageMs = result
    ? Math.max(...Object.values(result.cato.latency.stages), 0.1)
    : 0;

  return (
    <div className="avc-wrap">
      {/* ── Header ── */}
      <div className="avc-header card">
        <div className="avc-header-inner">
          <div>
            <h2 style={{ fontSize: 22, fontWeight: 800, marginBottom: 4 }}>AI vs CATO</h2>
            <p style={{ fontSize: 13, color: "var(--text-muted)", maxWidth: 560 }}>
              Compare what happens when a developer prompt is sent directly to an AI versus routed through CATO first.
            </p>
          </div>
          <div className="avc-banner">
            CATO = Pre-AI Policy Enforcement Layer
          </div>
        </div>
        <div className="avc-message">
          CATO does not replace Claude, GPT, Gemini or other AI assistants. It controls what is allowed to reach them.
        </div>
      </div>

      {/* ── Prompt input ── */}
      <div className="card" style={{ marginTop: 16 }}>
        <div className="section-title">Developer Prompt</div>
        <textarea
          className="avc-prompt"
          rows={5}
          value={prompt}
          onChange={e => setPrompt(e.target.value)}
        />
        <div className="avc-controls">
          <div className="avc-model-row">
            <span style={{ fontSize: 12, color: "var(--text-muted)", fontWeight: 600 }}>Target AI Model:</span>
            {AI_MODELS.map(m => (
              <button key={m.id} className={`model-btn ${model === m.id ? "model-active" : ""}`}
                onClick={() => setModel(m.id)}>
                {m.label}
              </button>
            ))}
          </div>
          <button className="btn btn-primary" onClick={handleCompare} disabled={loading || !prompt.trim()}>
            {loading ? <><span className="spinner" /> Comparing…</> : "⬡  Compare Direct AI vs CATO"}
          </button>
        </div>
        {error && <div className="error-msg" style={{ marginTop: 10 }}>⚠ {error}</div>}
        <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 8 }}>
          ⚠ Demonstration mode — no real credentials are transmitted to any external service.
        </div>
      </div>

      {/* ── Side-by-side comparison ── */}
      {result && (
        <>
          <div className="avc-split" style={{ marginTop: 16 }}>
            {/* Direct AI */}
            <div className="card avc-side avc-direct">
              <div className="avc-side-header">
                <span className="avc-side-icon">🤖</span>
                <div>
                  <div className="avc-side-title">Without CATO</div>
                  <div className="avc-side-sub">Direct AI — {result.direct.label}</div>
                </div>
              </div>

              <div className="avc-flow-steps">
                {["Developer writes prompt", "Prompt sent to AI service", "AI processes & responds"].map((s, i) => (
                  <div key={i} className="avc-flow-step">
                    <span className="avc-flow-num">{i + 1}</span>{s}
                  </div>
                ))}
              </div>

              <div className="avc-action-badge" style={{ background: "#fde8e8", border: "1px solid var(--red-border)", color: "var(--red)" }}>
                {result.direct.action_label}
              </div>

              {result.direct.secrets_exposed.length > 0 && (
                <div className="avc-exposed">
                  <div className="section-title" style={{ marginBottom: 6 }}>Secrets transmitted to AI:</div>
                  {result.direct.secrets_exposed.map((s, i) => (
                    <div key={i} className="avc-exposed-item">⚠ {s}</div>
                  ))}
                </div>
              )}

              <div className="section-title" style={{ marginTop: 14, marginBottom: 6 }}>Simulated AI Response</div>
              <pre className="avc-sim-response">{result.direct.simulated_response}</pre>
              <div className="avc-demo-label">{result.direct.warning}</div>
            </div>

            {/* CATO */}
            <div className="card avc-side avc-cato">
              <div className="avc-side-header">
                <img src="/cato-logo.png" alt="CATO" style={{ width: 36, height: 36, borderRadius: "50%", border: "2px solid var(--amber-border)" }} />
                <div>
                  <div className="avc-side-title">With CATO</div>
                  <div className="avc-side-sub">CATO Protected AI</div>
                </div>
              </div>

              <div className="avc-flow-steps">
                {["Developer writes prompt", "CATO Pre-AI Gateway", "Secret Detection", "PII Detection", "Prompt Injection Check", "Policy Evaluation", result.cato.action === "BLOCKED" ? "🚫 BLOCKED" : "✓ Forwarded to AI"].map((s, i) => (
                  <div key={i} className={`avc-flow-step ${s.startsWith("🚫") ? "step-block" : s.startsWith("✓") ? "step-approve" : ""}`}>
                    <span className="avc-flow-num">{i + 1}</span>{s}
                  </div>
                ))}
              </div>

              <div className="avc-action-badge" style={{
                background: result.cato.action === "BLOCKED" ? "var(--red-bg)" : result.cato.action === "SANITIZED" ? "var(--amber-bg)" : "var(--green-bg)",
                border: `1px solid ${result.cato.action === "BLOCKED" ? "var(--red-border)" : result.cato.action === "SANITIZED" ? "var(--amber-border)" : "var(--green-border)"}`,
                color: ACTION_COLOR[result.cato.action] ?? "var(--text)"
              }}>
                {result.cato.action} — {result.cato.action_label}
              </div>

              {result.cato.findings.length > 0 && (
                <div style={{ marginTop: 12 }}>
                  <div className="section-title" style={{ marginBottom: 6 }}>Findings detected:</div>
                  {result.cato.findings.map((f, i) => (
                    <div key={i} className="avc-finding">
                      <span className={`sev-badge sev-${f.severity.toLowerCase()}`}>{f.severity}</span>
                      <span style={{ flex: 1, fontSize: 12 }}>{f.title}</span>
                      <span style={{ fontSize: 11, fontWeight: 700, color: ACTION_COLOR[f.action] ?? "var(--text-muted)" }}>{f.action}</span>
                    </div>
                  ))}
                </div>
              )}

              {result.cato.action !== "BLOCKED" && (
                <div style={{ marginTop: 12 }}>
                  <div className="section-title" style={{ marginBottom: 4 }}>Sanitized Prompt</div>
                  <pre className="avc-sanitized">{result.cato.sanitized_prompt}</pre>
                </div>
              )}

              <div style={{ marginTop: 12 }}>
                <div className="section-title" style={{ marginBottom: 6 }}>
                  Pre-AI Latency (actual measured)
                  <span style={{ fontWeight: 400, color: "var(--text-muted)", marginLeft: 6 }}>
                    total: {result.cato.latency.total_ms} ms
                  </span>
                </div>
                {Object.entries(result.cato.latency.stages).map(([stage, ms]) => (
                  <LatencyBar key={stage} label={stage} ms={ms} maxMs={maxStageMs} />
                ))}
              </div>
            </div>
          </div>

          {/* Comparison table */}
          <div className="card" style={{ marginTop: 16 }}>
            <div className="section-title">Side-by-Side Comparison</div>
            <table className="compare-table">
              <thead>
                <tr>
                  <th>Metric</th>
                  <th>Direct AI</th>
                  <th>CATO Protected</th>
                </tr>
              </thead>
              <tbody>
                {result.comparison_table.map((row, i) => (
                  <tr key={i}>
                    <td>{row.metric}</td>
                    <td style={{ color: row.direct.startsWith("✗") ? "var(--red)" : "var(--text)" }}>{row.direct}</td>
                    <td style={{ color: row.cato.startsWith("✓") ? "var(--green)" : row.cato === "BLOCKED" ? "var(--red)" : "var(--amber)" }}>{row.cato}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="avc-key-message">💡 {result.key_message}</div>
          </div>
        </>
      )}

      {/* ── Latency Benchmark ── */}
      <div className="card" style={{ marginTop: 20 }}>
        <div className="section-title">CATO Pre-AI Latency Benchmark</div>
        <p style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 14 }}>
          All values measured with <code>time.perf_counter()</code>. No values are hardcoded.
        </p>

        <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 14, flexWrap: "wrap" }}>
          <label style={{ fontSize: 12, color: "var(--text-muted)", display: "flex", alignItems: "center", gap: 8 }}>
            Runs:
            <input type="number" min={5} max={100} value={benchRuns}
              onChange={e => setBenchRuns(Number(e.target.value))}
              style={{ width: 60, padding: "4px 8px", border: "1px solid var(--border)", borderRadius: 6, fontSize: 13, background: "var(--surface2)" }}
            />
          </label>
          <button className="btn btn-primary" onClick={handleBenchmark} disabled={benchLoading}>
            {benchLoading ? <><span className="spinner" /> Running…</> : "▶ Run Benchmark"}
          </button>
          <button className="btn btn-outline" onClick={handleSizeBenchmark} disabled={sizeLoading}>
            {sizeLoading ? <><span className="spinner" /> Running…</> : "Run Size Benchmark"}
          </button>
        </div>

        {benchResult && (
          <div className="bench-results">
            <div className="bench-stats">
              {[
                { label: "Runs",    value: benchResult.runs },
                { label: "Min",     value: `${benchResult.min_ms} ms` },
                { label: "Max",     value: `${benchResult.max_ms} ms` },
                { label: "Average", value: `${benchResult.avg_ms} ms` },
                { label: "Median",  value: `${benchResult.median_ms} ms` },
                { label: "Std Dev", value: `${benchResult.stdev_ms} ms` },
                { label: "Prompt",  value: `${benchResult.prompt_size_kb} KB` },
              ].map(s => (
                <div key={s.label} className="bench-stat">
                  <div className="bench-stat-val">{s.value}</div>
                  <div className="bench-stat-label">{s.label}</div>
                </div>
              ))}
            </div>

            <div style={{ marginTop: 16 }}>
              <div className="section-title" style={{ marginBottom: 8 }}>Per-Stage Averages</div>
              {Object.entries(benchResult.stage_averages_ms).map(([stage, ms]) => {
                const maxMs = Math.max(...Object.values(benchResult.stage_averages_ms), 0.1);
                return <LatencyBar key={stage} label={stage} ms={ms} maxMs={maxMs} />;
              })}
              <div className="bench-total">
                Total CATO Pre-AI Overhead: {benchResult.avg_ms} ms avg / {benchResult.median_ms} ms median
              </div>
            </div>

            <div style={{ marginTop: 14 }}>
              <div className="section-title" style={{ marginBottom: 4 }}>All {benchResult.runs} run times (ms)</div>
              <Sparkline data={benchResult.all_times_ms} />
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
                {benchResult.all_times_ms.join("  ")} ms
              </div>
            </div>
          </div>
        )}

        {sizeResults && (
          <div style={{ marginTop: 20 }}>
            <div className="section-title" style={{ marginBottom: 10 }}>Latency by Prompt Size (10 runs each)</div>
            <table className="compare-table">
              <thead>
                <tr><th>Prompt Size</th><th>Avg (ms)</th><th>Median (ms)</th><th>Min (ms)</th><th>Max (ms)</th></tr>
              </thead>
              <tbody>
                {Object.entries(sizeResults).map(([size, r]) => (
                  <tr key={size}>
                    <td style={{ fontWeight: 600, textTransform: "capitalize" }}>{size} ({r.prompt_size_kb} KB)</td>
                    <td>{r.avg_ms}</td>
                    <td>{r.median_ms}</td>
                    <td>{r.min_ms}</td>
                    <td>{r.max_ms}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="bench-note">
          <strong>Pre-AI checks</strong> (secret / PII / injection / policy) → <em>milliseconds</em><br />
          <strong>Post-AI checks</strong> (SAST / dependency scan / testing) → <em>seconds to minutes</em> depending on project size<br />
          Lightweight pre-AI checks are designed to add minimal latency. Heavier software verification runs asynchronously or at the CI/CD checkpoint.
        </div>
      </div>

      {/* ── Proof of Value ── */}
      <div className="card" style={{ marginTop: 16 }}>
        <div className="section-title">CATO — Proof of Value (This Session)</div>
        <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 14 }}>
          Populated from actual CATO runs in this session.
        </div>
        <div className="pov-grid">
          <div className="pov-card pov-sec">
            <div className="pov-title">Pre-AI Security</div>
            <div className="pov-stat">{povStats.secrets}<span>secrets detected</span></div>
            <div className="pov-stat">{povStats.blocked}<span>blocked</span></div>
            <div className="pov-stat">{povStats.sanitized}<span>sanitized</span></div>
          </div>
          <div className="pov-card pov-lat">
            <div className="pov-title">Latency</div>
            <div className="pov-stat">{benchResult?.avg_ms ?? "—"}<span>ms avg</span></div>
            <div className="pov-stat">{benchResult?.median_ms ?? "—"}<span>ms median</span></div>
            <div className="pov-stat">{benchResult?.runs ?? "—"}<span>benchmark runs</span></div>
          </div>
          <div className="pov-card pov-cost">
            <div className="pov-title">Cost (Estimates)</div>
            <div className="pov-stat" style={{ fontSize: 14 }}>₹4–6.5K<span>/month MVP</span></div>
            <div className="pov-stat" style={{ fontSize: 14 }}>₹35K<span>/month enterprise</span></div>
            <div className="pov-stat" style={{ fontSize: 14 }}>₹25K+<span>/month SaaS</span></div>
          </div>
        </div>
      </div>
    </div>
  );
}
