import { useEffect, useState } from "react";
import { getChain, verifyCertificate } from "../api.ts";
import type { BlockchainBlock } from "../api.ts";
import "./BlockchainView.css";

export default function BlockchainView() {
  const [chain, setChain]       = useState<BlockchainBlock[]>([]);
  const [valid, setValid]       = useState(true);
  const [mode, setMode]         = useState("");
  const [loading, setLoading]   = useState(true);
  const [input, setInput]       = useState("");
  const [verifyOk, setVerifyOk] = useState<boolean | null>(null);
  const [verifyBlock, setVerifyBlock] = useState<number | null>(null);
  const [verifyTs, setVerifyTs] = useState<string | null>(null);

  useEffect(() => {
    getChain().then(d => {
      setChain(d.chain);
      setValid(d.valid);
      setMode(d.mode);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  async function handleVerify() {
    if (!input.trim()) return;
    const r = await verifyCertificate(input.trim());
    setVerifyOk(r.verified);
    setVerifyBlock(r.block_index ?? null);
    setVerifyTs(r.timestamp ?? null);
  }

  if (loading) return <div style={{color:"var(--text-muted)", padding:40}}>Loading chain…</div>;

  return (
    <div>
      <div style={{ display:"flex", alignItems:"center", gap:14, marginBottom:20 }}>
        <div>
          <h2 style={{fontSize:20, fontWeight:700, marginBottom:4}}>🔗 Blockchain Registry</h2>
          <div style={{fontSize:12, color:"var(--text-muted)"}}>{mode}</div>
        </div>
        <div style={{marginLeft:"auto", display:"flex", gap:10, alignItems:"center"}}>
          <span className={`badge ${valid ? "badge-pass" : "badge-fail"}`}>
            Chain {valid ? "VALID" : "INVALID"}
          </span>
          <span style={{fontSize:12, color:"var(--text-muted)", padding:"4px 8px", background:"var(--surface2)", borderRadius:4}}>
            {chain.length} block{chain.length !== 1 ? "s" : ""}
          </span>
        </div>
      </div>

      {/* Verify tool */}
      <div className="card" style={{marginBottom:20}}>
        <div className="section-title">Verify Certificate Hash</div>
        <div style={{ display:"flex", gap:10, marginTop:8 }}>
          <input
            className="hash-input"
            placeholder="Paste SHA-256 certificate hash…"
            value={input}
            onChange={e => setInput(e.target.value)}
          />
          <button className="btn btn-primary" onClick={handleVerify}>Verify</button>
        </div>
        {verifyOk !== null && (
          <div className={`verify-result ${verifyOk ? "verify-ok" : "verify-fail"}`} style={{marginTop:12}}>
            {verifyOk
              ? <>✓ <strong>Hash found on chain</strong> — Block #{verifyBlock}, recorded {verifyTs ? new Date(verifyTs).toLocaleString() : ""}</>
              : "✗ Hash not found on chain — not registered or tampered"}
          </div>
        )}
      </div>

      {/* Chain blocks */}
      <div className="chain-list">
        {[...chain].reverse().map((block: BlockchainBlock) => (
          <div key={block.index} className={`chain-block card ${block.index === 0 ? "genesis-block" : ""}`}>
            <div className="block-header">
              <span className="block-index">#{block.index}</span>
              <span className="block-label">{block.index === 0 ? "GENESIS" : "CERTIFICATE BLOCK"}</span>
              <span style={{fontSize:11, color:"var(--text-muted)", marginLeft:"auto"}}>
                {new Date(block.timestamp).toLocaleString()}
              </span>
            </div>
            {block.index > 0 && (
              <div className="block-cert-id">
                Cert: <span style={{color:"var(--accent)", fontFamily:"monospace"}}>{block.certificate_id}</span>
              </div>
            )}
            <div className="block-hashes">
              <div className="block-hash-row">
                <span className="hash-label">Block Hash</span>
                <span className="hash-val">{block.block_hash}</span>
              </div>
              <div className="block-hash-row">
                <span className="hash-label">Prev Hash</span>
                <span className="hash-val dim">{block.previous_hash}</span>
              </div>
              {block.index > 0 && (
                <div className="block-hash-row">
                  <span className="hash-label">Cert Hash</span>
                  <span className="hash-val">{block.certificate_hash}</span>
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
