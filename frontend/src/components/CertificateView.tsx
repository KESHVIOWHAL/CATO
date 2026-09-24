import { useEffect, useState } from "react";
import { getCertificate, verifyCertificate } from "../api.ts";
import type { TrustCertificate, CheckResult } from "../api.ts";
import "./CertificateView.css";

interface Props {
  certId: string;
}

export default function CertificateView({ certId }: Props) {
  const [cert, setCert]           = useState<TrustCertificate | null>(null);
  const [verified, setVerified]   = useState<boolean | null>(null);
  const [blockIndex, setBlockIndex] = useState<number | null>(null);
  const [loading, setLoading]     = useState(true);

  useEffect(() => {
    getCertificate(certId)
      .then((c: TrustCertificate) => { setCert(c); setLoading(false); })
      .catch(() => setLoading(false));
  }, [certId]);

  async function handleVerify() {
    if (!cert) return;
    const r = await verifyCertificate(cert.certificate_hash);
    setVerified(r.verified);
    if (r.block_index !== undefined) setBlockIndex(r.block_index);
  }

  function handleDownload() {
    if (!cert) return;
    const blob = new Blob([JSON.stringify(cert, null, 2)], { type: "application/json" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url;
    a.download = `${cert.certificate_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  if (loading) return <div style={{color:"var(--text-muted)", padding:40}}>Loading certificate…</div>;
  if (!cert)   return <div style={{color:"var(--red)", padding:40}}>Certificate not found.</div>;

  const decisionColor =
    cert.decision === "BLOCK"   ? "var(--red)"   :
    cert.decision === "REVIEW"  ? "var(--amber)" :
    cert.decision === "APPROVE" ? "var(--green)" : "var(--text)";

  const decisionClass =
    cert.decision === "BLOCK"   ? "decision-block"  :
    cert.decision === "REVIEW"  ? "decision-review" :
    cert.decision === "APPROVE" ? "decision-approve": "";

  return (
    <div className="cert-page">
      <div className="cert-actions">
        <button className="btn btn-outline" onClick={handleDownload}>⬇ Download JSON</button>
        <button className="btn btn-primary" onClick={handleVerify}>🔗 Verify on Blockchain</button>
      </div>

      <div className="cert-card card">
        <div className="cert-header">
          <img src="/cato-logo.png" alt="CATO" style={{ width: 52, height: 52, borderRadius: "50%", border: "2px solid var(--amber-border)", marginBottom: 10 }} />
          <div className="cert-logo">CATO</div>
          <div className="cert-title">TRUST CERTIFICATE</div>
          <div className="cert-subtitle">Context-Aware Trust Orchestrator · SIH 2026 · ThinkTank</div>
        </div>

        <div className="divider" />

        <div className="cert-meta-grid">
          <div className="cert-meta-item">
            <div className="cert-label">Certificate ID</div>
            <div className="cert-value mono">{cert.certificate_id}</div>
          </div>
          <div className="cert-meta-item">
            <div className="cert-label">Project</div>
            <div className="cert-value">{cert.project_name}</div>
          </div>
          <div className="cert-meta-item">
            <div className="cert-label">Timestamp</div>
            <div className="cert-value">{new Date(cert.timestamp).toLocaleString()}</div>
          </div>
          <div className="cert-meta-item">
            <div className="cert-label">Risk Level</div>
            <div className="cert-value" style={{color: decisionColor}}>{cert.risk_level}</div>
          </div>
          <div className="cert-meta-item">
            <div className="cert-label">Trust Score</div>
            <div className="cert-value" style={{color: decisionColor, fontSize: 20, fontWeight: 800}}>{cert.trust_score} / 100</div>
          </div>
        </div>

        <div className="divider" />

        <div className={`cert-decision-block ${decisionClass}`}>
          <div className="cert-label" style={{marginBottom:6}}>Trust Decision</div>
          <div className="cert-decision-text" style={{color: decisionColor}}>{cert.decision}</div>
        </div>

        <div className="divider" />

        <div className="section-title">Security Checks</div>
        <div className="cert-checks">
          {cert.checks.map((c: CheckResult, i: number) => (
            <div key={i} className="cert-check-row">
              <span className={`cert-check-icon ${c.status === "PASS" ? "icon-pass" : "icon-fail"}`}>
                {c.status === "PASS" ? "✓" : "✗"}
              </span>
              <span className="cert-check-name">{c.check_name}</span>
              <span className={`badge ${c.status === "PASS" ? "badge-pass" : "badge-fail"}`}>{c.status}</span>
              <span className={`badge ${c.scan_mode === "DEMO" ? "badge-demo" : "badge-live"}`}>{c.scan_mode}</span>
            </div>
          ))}
        </div>

        {cert.findings_summary.length > 0 && (
          <>
            <div className="divider" />
            <div className="section-title">Findings</div>
            <ul className="cert-findings">
              {cert.findings_summary.map((f: string, i: number) => (
                <li key={i} className="cert-finding-item">{f}</li>
              ))}
            </ul>
          </>
        )}

        {cert.recommendations_summary && cert.recommendations_summary.length > 0 && (
          <>
            <div className="divider" />
            <div className="section-title">Recommendations</div>
            <ul className="cert-findings">
              {cert.recommendations_summary.map((r: string, i: number) => (
                <li key={i} className="cert-finding-item" style={{borderLeftColor: "var(--accent)"}}>{r}</li>
              ))}
            </ul>
          </>
        )}

        <div className="divider" />
        <div style={{ display:"flex", alignItems:"center", gap:10 }}>
          <span style={{ fontSize:22 }}>{cert.policy_passed ? "✓" : "✗"}</span>
          <span style={{ fontWeight:700, color: cert.policy_passed ? "var(--green)" : "var(--red)" }}>
            {cert.policy_passed ? "POLICY PASSED" : "POLICY FAILED"}
          </span>
        </div>

        <div className="divider" />

        <div className="section-title">Certificate Hash (SHA-256)</div>
        <div className="hash-box">{cert.certificate_hash}</div>
        <div style={{fontSize:11, color:"var(--text-muted)", marginTop:6}}>
          Any modification to this certificate will produce a different hash.
        </div>

        <div className="divider" />

        <div className="section-title">Blockchain Record</div>
        <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:8 }}>
          <span style={{fontSize:18}}>🔗</span>
          <span style={{fontWeight:700, color: cert.blockchain_status === "RECORDED" ? "var(--green)" : "var(--amber)"}}>
            {cert.blockchain_status}
          </span>
          <span className="badge badge-demo">DEMO CHAIN</span>
        </div>
        {cert.blockchain_tx && (
          <>
            <div style={{fontSize:11, color:"var(--text-muted)", marginBottom:4}}>Block Hash</div>
            <div className="hash-box" style={{fontSize:11}}>{cert.blockchain_tx}</div>
          </>
        )}

        {verified !== null && (
          <div className={`verify-result ${verified ? "verify-ok" : "verify-fail"}`} style={{marginTop:14}}>
            {verified
              ? <>✓ <strong>Blockchain Verified</strong> — Block #{blockIndex}</>
              : "✗ Hash not found on chain"}
          </div>
        )}
      </div>
    </div>
  );
}
