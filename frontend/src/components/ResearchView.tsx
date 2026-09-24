import { useState } from "react";
import "./ResearchView.css";

const PAPERS = [
  {
    title: "Lost at C: A User Study on the Security Implications of Large Language Model Code Assistants",
    authors: "Sandoval et al.",
    year: 2023,
    venue: "USENIX Security",
    problem: "LLM-generated code introduces security vulnerabilities including CWE-89, CWE-78, CWE-798",
    relevance: "Empirically shows AI-generated code contains real security flaws — the problem CATO addresses",
    gap: "Study identifies problems; CATO provides the orchestrated detection and governance layer",
  },
  {
    title: "Large Language Models for Code: Security Hardening and Adversarial Testing",
    authors: "He & Vechev",
    year: 2023,
    venue: "ACM CCS",
    problem: "LLM-generated code is vulnerable; fine-tuning on secure code reduces but does not eliminate flaws",
    relevance: "Validates that model-level fixes are insufficient — external verification layers remain necessary",
    gap: "Focuses on model training; CATO operates at the deployment/governance layer, model-agnostic",
  },
  {
    title: "Prompt Injection Attacks and Defenses in LLM-Integrated Applications",
    authors: "Liu et al.",
    year: 2024,
    venue: "arXiv / IEEE S&P",
    problem: "Prompt injection attacks in LLM pipelines allow attacker control of AI agents",
    relevance: "CATO's AI Interaction Protection layer addresses this class of attack pre-transmission",
    gap: "Focuses on attack taxonomy; CATO implements real-time detection and blocking",
  },
  {
    title: "Software Supply Chain Security: A Comprehensive Study",
    authors: "Ohm et al.",
    year: 2022,
    venue: "ACM Computing Surveys",
    problem: "Third-party dependency vulnerabilities are a primary software supply chain attack vector",
    relevance: "CATO's dependency analysis module (OSV.dev) addresses this directly",
    gap: "Survey scope; CATO integrates dependency checks into a unified trust decision",
  },
  {
    title: "OSV: A Scalable, Precise, and Open Vulnerability Database",
    authors: "Google Open Source Security Team",
    year: 2021,
    venue: "OSV.dev (Production System)",
    problem: "Fragmented, inconsistent vulnerability data across ecosystems",
    relevance: "CATO uses the OSV REST API for real-time CVE lookups against project dependencies",
    gap: "OSV provides data; CATO uses it as evidence in a broader trust decision pipeline",
  },
  {
    title: "Semgrep: Lightweight Static Analysis for Many Languages",
    authors: "Bai et al. / Semgrep Inc.",
    year: 2022,
    venue: "IEEE/ACM ICSE",
    problem: "SAST tools are complex, slow, or language-specific",
    relevance: "CATO integrates Semgrep (with AST-based fallback) as the SAST evidence source",
    gap: "Single-check tool; CATO aggregates SAST with 5 other evidence sources into one decision",
  },
  {
    title: "Towards Automated Software Trust: From Detection to Certification",
    authors: "Shafiq et al.",
    year: 2023,
    venue: "IEEE TrustCom",
    problem: "Individual security checks produce siloed results with no unified trust signal",
    relevance: "Directly motivates CATO's evidence orchestration approach",
    gap: "Proposes framework concepts; CATO provides a working prototype implementation",
  },
  {
    title: "An Empirical Study of Deep Learning Models for Vulnerability Detection",
    authors: "Chakraborty et al.",
    year: 2022,
    venue: "ICSE 2022",
    problem: "ML-based vulnerability detection has limited precision and high false-positive rates",
    relevance: "Validates need for rule-based + ML hybrid approaches — CATO uses rule-based decision engine",
    gap: "Model evaluation only; CATO uses deterministic policy engine on top of multiple scanner evidence",
  },
];

const MATRIX = [
  { category: "AI-generated code security",         existing: "Sandoval et al., He & Vechev",         focus: "Measuring & reducing LLM code vulnerabilities", cato: "Detects flaws in generated output + governs before generation" },
  { category: "Prompt injection / LLM security",    existing: "Liu et al., OWASP LLM Top 10",         focus: "Attack taxonomy, prompt sanitization",          cato: "Real-time pre-AI detection, blocking, and sanitization" },
  { category: "Software supply-chain security",     existing: "Ohm et al., SLSA Framework",           focus: "Dependency provenance, build integrity",         cato: "Live CVE lookup via OSV.dev integrated into trust decision" },
  { category: "Dependency vulnerability scanning",  existing: "OSV, Snyk, Dependabot",                focus: "CVE detection per package",                     cato: "Normalised into evidence with severity-based policy gates" },
  { category: "Static analysis / SAST",             existing: "Semgrep, CodeQL, SonarQube",           focus: "Code pattern matching, AST analysis",           cato: "SAST is one of six evidence sources in unified decision" },
  { category: "AI coding assistants",               existing: "GitHub Copilot, Cursor, Claude, GPT",  focus: "Code generation and completion",                 cato: "CATO wraps them as a trust and governance layer" },
  { category: "Automated code review",              existing: "ReviewBot, DeepCode, Qodo",            focus: "Code quality and style",                        cato: "Security-focused evidence collection → explainable decision" },
  { category: "Policy / governance",                existing: "OPA, Kyverno, Styra",                  focus: "Infrastructure policy enforcement",              cato: "Application-level policy from cato-policy.json per project" },
  { category: "Security provenance / auditability", existing: "SLSA, in-toto, Sigstore",              focus: "Build and artifact provenance",                 cato: "Evidence chain from requirements → code → deps → tests → cert" },
];

const AI_COMPARE = [
  { capability: "Code generation",                  ai: "✓",                   cato: "—" },
  { capability: "Prompt understanding",             ai: "✓",                   cato: "✓" },
  { capability: "Pre-AI secret detection",          ai: "Provider-dependent",  cato: "✓" },
  { capability: "PII detection",                    ai: "Provider-dependent",  cato: "✓" },
  { capability: "Organisation-specific policy",     ai: "Provider-dependent",  cato: "✓" },
  { capability: "Prompt injection analysis",        ai: "Provider-dependent",  cato: "✓" },
  { capability: "Sanitization before transmission", ai: "Provider-dependent",  cato: "✓" },
  { capability: "Static analysis / SAST",           ai: "—",                   cato: "✓" },
  { capability: "Dependency vulnerability scan",    ai: "—",                   cato: "✓" },
  { capability: "Functional test execution",        ai: "—",                   cato: "✓" },
  { capability: "Architecture compliance check",    ai: "—",                   cato: "✓" },
  { capability: "Evidence & provenance chain",      ai: "—",                   cato: "✓" },
  { capability: "APPROVE / REVIEW / BLOCK decision","ai": "—",                 cato: "✓" },
  { capability: "Explainable trust decision",       ai: "—",                   cato: "✓" },
  { capability: "SHA-256 trust certificate",        ai: "—",                   cato: "✓" },
  { capability: "Blockchain-backed proof",          ai: "—",                   cato: "✓" },
];

export default function ResearchView() {
  const [tab, setTab] = useState<"matrix" | "papers" | "aicompare">("matrix");

  return (
    <div className="research-wrap">
      <div style={{ marginBottom: 24 }}>
        <h2 style={{ fontSize: 22, fontWeight: 800, marginBottom: 6 }}>Research &amp; Competitive Landscape</h2>
        <p style={{ fontSize: 13, color: "var(--text-muted)", maxWidth: 700, lineHeight: 1.6 }}>
          Existing research addresses AI-generated code security, prompt injection, and supply-chain risks through individual techniques or focused systems.
          CATO's proposed contribution is the <strong>orchestration of heterogeneous evidence</strong> with application context, organisational policy, and provenance
          into an <strong>explainable trust decision</strong>.
        </p>
      </div>

      {/* CATO positioning statement */}
      <div className="research-banner card">
        <div className="rb-left">
          <div className="rb-title">AI generates. CATO verifies and governs.</div>
          <div className="rb-sub">
            CATO does not replace GPT, Claude, Gemini or other AI assistants.<br />
            CATO acts as an independent security and trust layer around them.
          </div>
        </div>
        <div className="rb-flow">
          <div className="rb-box rb-ai">GPT / Claude / Gemini<span>AI Generation</span></div>
          <div className="rb-plus">+</div>
          <div className="rb-box rb-cato">CATO<span>Security · Governance · Verification</span></div>
          <div className="rb-eq">=</div>
          <div className="rb-box rb-result">Model-agnostic<br />Trust Layer</div>
        </div>
      </div>

      {/* Tabs */}
      <div className="research-tabs">
        {(["matrix", "papers", "aicompare"] as const).map(t => (
          <button key={t} className={`result-tab ${tab === t ? "result-tab-active" : ""}`}
            onClick={() => setTab(t)}>
            {t === "matrix"    ? "Competitive Matrix" :
             t === "papers"    ? `Research Papers (${PAPERS.length})` :
             "vs Licensed AI"}
          </button>
        ))}
      </div>

      {/* Matrix tab */}
      {tab === "matrix" && (
        <div className="card" style={{ marginTop: 0 }}>
          <div className="section-title" style={{ marginBottom: 12 }}>Security Research Categories — CATO Position</div>
          <div className="matrix-table-wrap">
            <table className="matrix-table">
              <thead>
                <tr>
                  <th>Category</th>
                  <th>Existing Work / Tools</th>
                  <th>Their Focus</th>
                  <th>CATO Contribution</th>
                </tr>
              </thead>
              <tbody>
                {MATRIX.map((row, i) => (
                  <tr key={i}>
                    <td className="mt-category">{row.category}</td>
                    <td className="mt-existing">{row.existing}</td>
                    <td className="mt-focus">{row.focus}</td>
                    <td className="mt-cato">{row.cato}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="research-note">
            CATO does not claim to be without precedent in any individual category.
            The research gap is in <strong>orchestrating multiple heterogeneous evidence sources with organisational policy context
            into a single explainable trust decision with cryptographic proof</strong>.
          </div>
        </div>
      )}

      {/* Papers tab */}
      {tab === "papers" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 10, marginTop: 0 }}>
          {PAPERS.map((p, i) => (
            <div key={i} className="paper-card card">
              <div className="paper-header">
                <div className="paper-year">{p.year}</div>
                <div className="paper-venue">{p.venue}</div>
              </div>
              <div className="paper-title">{p.title}</div>
              <div className="paper-authors">{p.authors}</div>
              <div className="paper-rows">
                <div className="paper-row">
                  <span className="paper-label">Problem</span>
                  <span className="paper-val">{p.problem}</span>
                </div>
                <div className="paper-row">
                  <span className="paper-label">Relevance to CATO</span>
                  <span className="paper-val" style={{ color: "var(--green)" }}>{p.relevance}</span>
                </div>
                <div className="paper-row">
                  <span className="paper-label">CATO distinction</span>
                  <span className="paper-val" style={{ color: "var(--accent)" }}>{p.gap}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* AI compare tab */}
      {tab === "aicompare" && (
        <div className="card" style={{ marginTop: 0 }}>
          <div className="section-title" style={{ marginBottom: 4 }}>CATO vs Licensed AI Assistants</div>
          <p style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 16, lineHeight: 1.6 }}>
            "Provider-dependent" means the capability may exist in some providers or configurations but is not a standard,
            organisation-configurable guarantee. CATO provides these as explicit, auditable, policy-driven controls.
          </p>
          <table className="compare-table">
            <thead>
              <tr>
                <th>Capability</th>
                <th>Licensed AI (GPT / Claude / Gemini)</th>
                <th>CATO</th>
              </tr>
            </thead>
            <tbody>
              {AI_COMPARE.map((row, i) => (
                <tr key={i}>
                  <td>{row.capability}</td>
                  <td style={{
                    color: row.ai === "✓" ? "var(--green)" :
                           row.ai === "—" ? "var(--text-muted)" : "var(--amber)"
                  }}>{row.ai}</td>
                  <td style={{ color: row.cato === "✓" ? "var(--green)" : "var(--text-muted)" }}>{row.cato}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="research-note" style={{ marginTop: 14 }}>
            This comparison reflects CATO's role as a <strong>pre-AI and post-AI governance layer</strong>, not a replacement for AI assistants.
            Licensed AI models have strong capabilities in code generation and understanding; CATO adds the security and trust enforcement layer that organisations require.
          </div>
        </div>
      )}
    </div>
  );
}
