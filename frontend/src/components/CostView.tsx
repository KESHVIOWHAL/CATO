import "./CostView.css";

const MVP_COSTS = [
  { item: "Development tools (Python, Node, VS Code)", cost: "₹0" },
  { item: "FastAPI / React / TypeScript", cost: "₹0" },
  { item: "Gitleaks / Semgrep CE / OSV / pytest", cost: "₹0" },
  { item: "Git / GitHub", cost: "₹0 – ₹1,000/month" },
  { item: "Cloud compute (e.g. AWS t3.small / Azure B1s)", cost: "₹2,000 – ₹5,000/month" },
  { item: "Database / object storage", cost: "₹1,000 – ₹2,000/month" },
  { item: "Domain & miscellaneous", cost: "₹1,000 – ₹2,000/year" },
  { item: "Blockchain test environment", cost: "₹0 – ₹500/month" },
];

const PLANS = [
  {
    name: "CATO STARTER",
    price: "₹25,000",
    period: "/month",
    color: "var(--green)",
    bg: "var(--green-bg)",
    border: "var(--green-border)",
    features: [
      "Small development teams",
      "Limited analysis volume",
      "Basic security policies",
      "Trust certificates",
      "Email support",
    ],
  },
  {
    name: "CATO BUSINESS",
    price: "₹75,000",
    period: "/month",
    color: "var(--accent)",
    bg: "var(--accent-bg)",
    border: "var(--amber-border)",
    features: [
      "Multiple repositories",
      "CI/CD integration",
      "Advanced security policies",
      "Evidence & provenance graph",
      "Trust certificates",
      "Priority support",
    ],
    highlight: true,
  },
  {
    name: "CATO ENTERPRISE",
    price: "₹2L – ₹5L+",
    period: "/month",
    color: "var(--blue)",
    bg: "var(--blue-bg)",
    border: "var(--blue-border)",
    features: [
      "Private / on-premise deployment",
      "Custom security policies",
      "Enterprise integrations",
      "Advanced audit capabilities",
      "Dedicated support",
      "Custom SLA",
    ],
  },
];

const REVENUE_STREAMS = [
  { icon: "📦", title: "SaaS Subscription", desc: "Monthly/annual plans per team or repository" },
  { icon: "📊", title: "Usage-Based Analysis", desc: "Per-scan pricing for high-volume customers" },
  { icon: "🏢", title: "Enterprise Licensing", desc: "Annual license for unlimited internal use" },
  { icon: "🖥", title: "On-Premise / Private", desc: "Airgapped deployment for regulated industries" },
];

export default function CostView() {
  return (
    <div className="cost-wrap">
      <div style={{ marginBottom: 24 }}>
        <h2 style={{ fontSize: 22, fontWeight: 800, marginBottom: 6 }}>CATO — Cost &amp; Business Model</h2>
        <p style={{ fontSize: 13, color: "var(--text-muted)" }}>
          Illustrative estimates — to be validated during pilot deployment.
        </p>
      </div>

      {/* Business message */}
      <div className="cost-message card">
        <div className="cost-message-title">CATO is sold as a Security &amp; Trust Layer as a Service</div>
        <div className="cost-message-sub">
          Organizations do not replace their existing AI, security scanners, repositories or CI/CD systems.
          CATO integrates with them as a policy-aware trust layer.
        </div>
      </div>

      {/* MVP + Pilot grid */}
      <div className="cost-grid" style={{ marginTop: 20 }}>
        {/* MVP */}
        <div className="card">
          <div className="section-title">A. Student MVP Cost</div>
          <div className="cost-note">Open-source tools assumed. Cloud/API usage may vary.</div>
          <table className="cost-table">
            <tbody>
              {MVP_COSTS.map((r, i) => (
                <tr key={i}>
                  <td>{r.item}</td>
                  <td className="cost-val">{r.cost}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="cost-total">
            <span>Estimated MVP Infrastructure</span>
            <span className="cost-total-val">₹4,000 – ₹9,000/month</span>
          </div>
        </div>

        {/* Pilot + Enterprise */}
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <div className="card">
            <div className="section-title">B. Small Pilot Deployment</div>
            <div className="cost-note">Varies by developer count, scan frequency, compute, storage, and AI/API usage.</div>
            <div className="cost-total" style={{ marginTop: 8 }}>
              <span>Estimated Pilot Range</span>
              <span className="cost-total-val">₹50,000 – ₹1.5L/month</span>
            </div>
            <ul style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 10, paddingLeft: 16, lineHeight: 2 }}>
              <li>Number of developers & repositories</li>
              <li>Scan frequency</li>
              <li>Compute & storage</li>
              <li>Monitoring & logging</li>
              <li>AI model / API usage cost</li>
            </ul>
          </div>

          <div className="card">
            <div className="section-title">C. Enterprise Deployment</div>
            <div style={{ fontSize: 13, color: "var(--text-muted)", lineHeight: 1.7 }}>
              Enterprise deployment is <strong>quote-based</strong>. Key factors:
            </div>
            <ul style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 8, paddingLeft: 16, lineHeight: 2 }}>
              <li>On-premise / private infrastructure</li>
              <li>Repository volume & developer count</li>
              <li>Compliance requirements</li>
              <li>AI model usage & licensing</li>
              <li>High availability & dedicated support</li>
            </ul>
          </div>
        </div>
      </div>

      {/* Pricing plans */}
      <div style={{ marginTop: 24 }}>
        <div className="section-title" style={{ marginBottom: 16 }}>
          Proposed SaaS Pricing
          <span style={{ fontWeight: 400, marginLeft: 8, color: "var(--text-muted)" }}>
            — Proposed initial pricing, subject to customer/pilot validation
          </span>
        </div>
        <div className="plans-grid">
          {PLANS.map(p => (
            <div key={p.name} className={`plan-card card ${p.highlight ? "plan-highlight" : ""}`}
              style={{ borderColor: p.border }}>
              {p.highlight && <div className="plan-badge">Most Popular</div>}
              <div className="plan-name" style={{ color: p.color }}>{p.name}</div>
              <div className="plan-price" style={{ color: p.color }}>
                {p.price}<span className="plan-period">{p.period}</span>
              </div>
              <ul className="plan-features">
                {p.features.map((f, i) => (
                  <li key={i}><span style={{ color: p.color }}>✓</span> {f}</li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>

      {/* Revenue model */}
      <div className="card" style={{ marginTop: 20 }}>
        <div className="section-title">Revenue Model</div>
        <div className="revenue-grid">
          {REVENUE_STREAMS.map((r, i) => (
            <div key={i} className="revenue-card">
              <span style={{ fontSize: 24 }}>{r.icon}</span>
              <div>
                <div style={{ fontWeight: 700, fontSize: 14 }}>{r.title}</div>
                <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 2 }}>{r.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
