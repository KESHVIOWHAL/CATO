import "./ArchView.css";

const LEFT_PANEL = [
  { label: "Developer Input",              sub: "Prompts · Source Code · Files · Project Context · Requirements",  icon: "💻" },
  { label: "AI Interaction Protection",    sub: "Secret Detection · Sensitive Context · Prompt/Agent Risk · Policy", icon: "🛡", highlight: true },
  { label: "DETECT → SANITIZE → BLOCK → ROUTE", sub: "Action layer before AI receives any input",                icon: "⚡", action: true },
  { label: "Sanitization & AI Routing",   sub: "Local AI / Enterprise AI / Approved Ext. AI",                   icon: "🔀" },
  { label: "AI-Generated Output",          sub: "Code · Configurations · Dependencies · Tests · Artifacts",       icon: "🤖" },
  { label: "CATO",                         sub: "Protect → Correlate → Verify → Decide → Certify",               icon: "⬡", cato: true },
];

const RIGHT_CHECKS = [
  { num: "1", label: "Requirement & Intent",  items: ["Requirement Match", "Intent Alignment", "Missing / Extra Functionality", "Traceability"], color: "#fde68a" },
  { num: "2", label: "Architecture & Policy", items: ["Architecture Rules", "Design Compliance", "Policy Compliance", "Layer Validation"],       color: "#a5f3fc" },
  { num: "3", label: "Security Verification", items: ["Vulnerability Scan", "Secure Coding", "Misconfigurations", "Security Best Practices"],   color: "#fca5a5" },
  { num: "4", label: "Dependency Trust",      items: ["Package Existence", "Vulnerabilities", "License & Reputation", "Provenance", "Package Trust Score"], color: "#bbf7d0" },
  { num: "5", label: "Static Analysis",       items: ["Code Quality", "Bugs / Smells", "Complexity", "Standards Checks"],                       color: "#c4b5fd" },
  { num: "6", label: "Testing",               items: ["Unit Tests", "Integration Tests", "Coverage", "Test Results"],                           color: "#fed7aa" },
];

const OUTCOMES = [
  { label: "APPROVE",          color: "var(--green)",  sub: "",                                 icon: "✓" },
  { label: "REVIEW",           color: "var(--amber)",  sub: "→ Human Approval Required",        icon: "○" },
  { label: "BLOCK",            color: "var(--red)",    sub: "STOP / QUARANTINE — does not proceed", icon: "⊗" },
];

const FUTURE = [
  "Containers", "AppArmor", "eBPF", "auditd", "Git Hooks",
];

export default function ArchView() {
  return (
    <div className="arch-full">
      <div style={{ marginBottom: 24 }}>
        <h2 style={{ fontSize: 20, fontWeight: 700, marginBottom: 6 }}>CATO — Full System Architecture</h2>
        <p style={{ color: "var(--text-muted)", fontSize: 13 }}>
          Complete architecture as designed. Implemented components shown in full colour. Future modules shown dimmed.
        </p>
      </div>

      <div className="arch-layout">

        {/* ── LEFT PANEL ── */}
        <div className="arch-left">
          <div className="arch-panel-title">Input & Protection Layer</div>
          {LEFT_PANEL.map((item, i) => (
            <div key={i}>
              <div className={`arch-left-step card ${item.highlight ? "arch-highlight" : ""} ${item.action ? "arch-action" : ""} ${item.cato ? "arch-cato" : ""}`}>
                <span style={{ fontSize: 18 }}>{item.icon}</span>
                <div>
                  <div style={{ fontWeight: 700, fontSize: 13 }}>{item.label}</div>
                  <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>{item.sub}</div>
                </div>
              </div>
              {i < LEFT_PANEL.length - 1 && <div className="arch-down-arrow">↓</div>}
            </div>
          ))}

          <div className="arch-down-arrow">↓</div>
          <div className="card" style={{ background: "#0a1a12", border: "1px solid #166534", padding: "10px 14px" }}>
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>Policies &amp; Context</div>
            {["Organization Policies", "Architecture Standards", "Security Policies", "Compliance Rules", "Coding Standards"].map((p, i) => (
              <div key={i} style={{ fontSize: 11, color: "var(--text-dim)" }}>· {p}</div>
            ))}
          </div>
        </div>

        {/* ── RIGHT PANEL ── */}
        <div className="arch-right">
          {/* 6 checks grid */}
          <div className="checks-grid">
            {RIGHT_CHECKS.map(c => (
              <div key={c.num} className="check-box card" style={{ borderTop: `3px solid ${c.color}33` }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                  <span style={{ background: c.color, color: "#000", borderRadius: 4, padding: "1px 7px", fontWeight: 800, fontSize: 12 }}>{c.num}</span>
                  <span style={{ fontWeight: 700, fontSize: 12 }}>{c.label}</span>
                </div>
                {c.items.map((item, i) => (
                  <div key={i} style={{ fontSize: 11, color: "var(--text-muted)" }}>· {item}</div>
                ))}
              </div>
            ))}
          </div>

          {/* Provenance */}
          <div className="card arch-prov" style={{ marginTop: 12 }}>
            <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 8 }}>Evidence &amp; Provenance Graph</div>
            <div className="prov-flow">
              {["Requirements", "Code", "Dependencies", "Security", "Tests", "Runtime"].map((s, i, arr) => (
                <span key={i} style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <span className="prov-tag">{s}</span>
                  {i < arr.length - 1 && <span style={{ color: "var(--border)" }}>→</span>}
                </span>
              ))}
            </div>
            <div style={{ fontSize: 11, color: "var(--accent)", marginTop: 6 }}>— — — TRACEABLE EVIDENCE — — —</div>
          </div>

          {/* Decision Engine */}
          <div className="card arch-decision" style={{ marginTop: 12 }}>
            <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 6 }}>Trust Decision Engine</div>
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 12 }}>Policy Gates · Evidence · Risk · Confidence</div>
            <div className="outcome-row">
              {OUTCOMES.map(o => (
                <div key={o.label} className="outcome-box" style={{ borderColor: o.color }}>
                  <div style={{ fontSize: 22, color: o.color }}>{o.icon}</div>
                  <div style={{ fontWeight: 800, color: o.color, fontSize: 13 }}>{o.label}</div>
                  {o.sub && <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 4 }}>{o.sub}</div>}
                </div>
              ))}
            </div>
          </div>

          {/* Certificate */}
          <div className="card arch-cert" style={{ marginTop: 12 }}>
            <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 4 }}>Explainable Trust Certificate</div>
            <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
              Decision &amp; Rationale · Evidence &amp; Provenance · Risk &amp; Policy Findings · Verification Coverage · Audit Trail
            </div>
            <div style={{ display: "flex", gap: 8, marginTop: 10, flexWrap: "wrap" }}>
              {["SHA-256 Hash", "Blockchain Registry", "Git / CI-CD Pipeline"].map(s => (
                <span key={s} className="cert-flow-tag">{s}</span>
              ))}
            </div>
          </div>

          {/* Linux Security */}
          <div className="card arch-linux" style={{ marginTop: 12 }}>
            <div style={{ fontWeight: 700, fontSize: 12, color: "var(--text-muted)", marginBottom: 8 }}>
              Linux Security &amp; Enforcement Foundation
              <span style={{ marginLeft: 8, fontSize: 10, color: "var(--border)" }}>(Future Modules)</span>
            </div>
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
              {FUTURE.map(f => (
                <span key={f} style={{ fontSize: 11, color: "var(--border)", background: "var(--surface2)", padding: "3px 10px", borderRadius: 4 }}>{f}</span>
              ))}
            </div>
            <div style={{ fontSize: 10, color: "var(--border)", marginTop: 6 }}>
              Isolation · Monitoring · Enforcement · Auditability
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
