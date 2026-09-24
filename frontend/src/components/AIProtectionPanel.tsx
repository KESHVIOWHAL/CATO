import { useState } from "react";
import { checkAIProtection } from "../api.ts";
import type { AIProtectionResult, AIProtectionFinding } from "../api.ts";
import "./AIProtectionPanel.css";

const ROUTING_LABEL: Record<string, { label: string; color: string; icon: string }> = {
  BLOCKED:           { label: "BLOCKED — Input rejected before AI routing", color: "var(--red)",   icon: "🚫" },
  LOCAL_AI:          { label: "Route to LOCAL AI (on-prem / offline)",       color: "var(--amber)", icon: "🖥" },
  ENTERPRISE_AI:     { label: "Route to ENTERPRISE AI (private / controlled)", color: "var(--amber)", icon: "🏢" },
  APPROVED_EXT_AI:   { label: "Route to APPROVED EXTERNAL AI",               color: "var(--green)", icon: "✓" },
};

const ACTION_COLOR: Record<string, string> = {
  BLOCK:    "var(--red)",
  SANITIZE: "var(--amber)",
  WARN:     "#d97706",
};

export default function AIProtectionPanel() {
  const [input, setInput]       = useState("");
  const [result, setResult]     = useState<AIProtectionResult | null>(null);
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState<string | null>(null);

  async function handleCheck() {
    if (!input.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const r = await checkAIProtection(input);
      setResult(r);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to check input");
    } finally {
      setLoading(false);
    }
  }

  const routing = result ? ROUTING_LABEL[result.routing] : null;

  return (
    <div className="aip-wrap">
      <div style={{ marginBottom: 20 }}>
        <h2 style={{ fontSize: 20, fontWeight: 700, marginBottom: 6 }}>
          AI Interaction Protection
        </h2>
        <p style={{ fontSize: 13, color: "var(--text-muted)" }}>
          Paste a developer prompt, source code snippet, or context text. CATO will detect secrets,
          sensitive data, and prompt injection attempts before it reaches any AI model.
        </p>
      </div>

      {/* Architecture flow */}
      <div className="aip-flow card">
        {["Developer Input", "Secret & Credential Detection", "Sensitive Context Detection", "Prompt / Agent Risk Analysis", "Policy Evaluation", "DETECT → SANITIZE → BLOCK → ROUTE"].map((step, i, arr) => (
          <div key={i} style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div className={`aip-flow-step ${i === arr.length - 1 ? "aip-flow-action" : ""}`}>{step}</div>
            {i < arr.length - 1 && <span style={{ color: "var(--border)" }}>→</span>}
          </div>
        ))}
      </div>

      {/* Routing destinations */}
      <div className="aip-routing-row card" style={{ marginTop: 12 }}>
        <div className="section-title" style={{ marginBottom: 10 }}>Sanitization &amp; Risk-Based AI Routing</div>
        <div className="routing-boxes">
          {[
            { id: "LOCAL_AI",        label: "Local AI",        sub: "On-Prem / Offline",         color: "#1a2e1a" },
            { id: "ENTERPRISE_AI",   label: "Enterprise AI",   sub: "Private / Controlled",       color: "#1a1a2e" },
            { id: "APPROVED_EXT_AI", label: "Approved Ext. AI",sub: "Trusted Providers",          color: "#0d1a2e" },
          ].map(box => (
            <div key={box.id} className={`routing-box ${result?.routing === box.id ? "routing-active" : ""}`}
              style={{ background: box.color }}>
              <div className="routing-box-label">{box.label}</div>
              <div className="routing-box-sub">{box.sub}</div>
              {result?.routing === box.id && <div className="routing-selected">← ROUTED</div>}
            </div>
          ))}
        </div>
      </div>

      {/* Input area */}
      <div className="card" style={{ marginTop: 12 }}>
        <div className="section-title">Test Developer Input</div>
        <textarea
          className="aip-input"
          rows={6}
          placeholder="Paste a prompt, code snippet, or context... e.g. 'My database password is admin123, please generate code to connect to it'"
          value={input}
          onChange={e => setInput(e.target.value)}
        />
        <button className="btn btn-primary" style={{ marginTop: 10 }} onClick={handleCheck} disabled={loading || !input.trim()}>
          {loading ? <><span className="spinner" /> Analyzing…</> : "⬡  Run AI Protection Check"}
        </button>
        {error && <div className="error-msg" style={{ marginTop: 10 }}>⚠ {error}</div>}
      </div>

      {/* Result */}
      {result && (
        <div className="card" style={{ marginTop: 12 }}>
          <div className="section-title">Protection Result</div>

          {/* Routing decision */}
          {routing && (
            <div className={`aip-result-banner ${result.blocked ? "aip-blocked" : "aip-allowed"}`}>
              <span style={{ fontSize: 22 }}>{routing.icon}</span>
              <div>
                <div style={{ fontWeight: 700, color: routing.color }}>{routing.label}</div>
                <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 2 }}>{result.summary}</div>
              </div>
            </div>
          )}

          {/* Findings */}
          {result.findings.length > 0 && (
            <div style={{ marginTop: 14 }}>
              <div className="section-title">Detected Issues</div>
              <div className="aip-findings">
                {result.findings.map((f: AIProtectionFinding, i: number) => (
                  <div key={i} className="aip-finding">
                    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
                      <span className={`sev-badge sev-${f.severity.toLowerCase()}`}>{f.severity}</span>
                      <span style={{ fontWeight: 600, fontSize: 13 }}>{f.title}</span>
                      <span style={{
                        marginLeft: "auto", fontSize: 11, fontWeight: 700,
                        color: ACTION_COLOR[f.action] ?? "var(--text-muted)"
                      }}>
                        {f.action}
                      </span>
                    </div>
                    <div style={{ fontSize: 12, color: "var(--text-muted)" }}>{f.description}</div>
                    <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
                      Category: {f.category.replace("_", " ")} · Line {f.line}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {result.findings.length === 0 && (
            <div style={{ marginTop: 12, color: "var(--green)", fontSize: 13 }}>
              ✓ No issues detected — input is safe for AI routing
            </div>
          )}
        </div>
      )}
    </div>
  );
}
