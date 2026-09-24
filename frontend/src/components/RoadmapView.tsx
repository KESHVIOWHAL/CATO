import "./RoadmapView.css";

const CURRENT = [
  "Secret Detection (DEMO MODE → LIVE with Gitleaks)",
  "Static Analysis / SAST (DEMO MODE → LIVE with Semgrep)",
  "Dependency Vulnerability Scan (DEMO MODE → LIVE with OSV-Scanner)",
  "Functional Test Runner (LIVE — pytest)",
  "Normalized Evidence Model",
  "Rule-Based Decision Engine (CRITICAL/HIGH → BLOCK)",
  "Trust Certificate with SHA-256 Hash",
  "In-Memory Blockchain Registry (Demo Chain)",
  "Certificate Verification",
  "APPROVE / REVIEW / BLOCK Dashboard",
];

const FUTURE = [
  { label: "Prompt & Context Protection",     desc: "Detect prompt injection in AI inputs before code generation" },
  { label: "Requirement & Intent Verification", desc: "Validate code implements what was actually requested" },
  { label: "Architecture Compliance",         desc: "Check code structure against approved patterns" },
  { label: "Evidence & Provenance Graph",     desc: "Neo4j-powered audit trail from prompt to deployment" },
  { label: "Docker Isolation",                desc: "Sandboxed execution environment for AI-generated code" },
  { label: "AppArmor / seccomp",              desc: "OS-level syscall restrictions during execution" },
  { label: "eBPF Runtime Monitoring",         desc: "Kernel-level behavioral analysis during execution" },
  { label: "auditd Integration",              desc: "Persistent audit logging of all execution events" },
  { label: "Git Hooks",                       desc: "Automatic CATO analysis on commit / pre-push" },
  { label: "CI/CD Pipeline Integration",      desc: "GitHub Actions / GitLab CI gate with CATO decision" },
  { label: "Local / Enterprise LLM Routing",  desc: "Air-gapped deployment with on-premise model support" },
  { label: "Dynamic Runtime Analysis",        desc: "Behavioral testing of AI code in isolation" },
  { label: "Production Blockchain Network",   desc: "Ethereum/Polygon smart contract: TrustRegistry.sol" },
  { label: "Multi-User & RBAC",               desc: "Team dashboards, role-based access, audit reports" },
];

export default function RoadmapView() {
  return (
    <div>
      <div style={{ marginBottom: 28 }}>
        <h2 style={{ fontSize: 20, fontWeight: 700, marginBottom: 6 }}>CATO — Roadmap</h2>
        <p style={{ fontSize: 13, color: "var(--text-muted)" }}>
          What is implemented today vs. what is planned for future stages.
        </p>
      </div>

      <div className="roadmap-grid">
        <div className="card">
          <div className="section-title" style={{ color: "var(--green)" }}>✓ Implemented (Prototype)</div>
          <ul className="roadmap-list">
            {CURRENT.map((item, i) => (
              <li key={i} className="roadmap-item roadmap-done">
                <span className="rm-dot dot-green" />
                {item}
              </li>
            ))}
          </ul>
        </div>

        <div className="card">
          <div className="section-title" style={{ color: "var(--accent)" }}>◷ Planned Future Modules</div>
          <ul className="roadmap-list">
            {FUTURE.map((item, i) => (
              <li key={i} className="roadmap-item roadmap-planned">
                <span className="rm-dot dot-blue" />
                <div>
                  <div className="rm-label">{item.label}</div>
                  <div className="rm-desc">{item.desc}</div>
                </div>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}
