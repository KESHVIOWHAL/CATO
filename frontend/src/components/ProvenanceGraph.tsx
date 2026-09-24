import type { ProvenanceGraph } from "../api.ts";
import "./ProvenanceGraph.css";

const STAGE_ICON: Record<string, string> = {
  REQUIREMENT: "📋",
  CODE:        "💻",
  DEPENDENCY:  "📦",
  SECURITY:    "🔑",
  TEST:        "🧪",
  RUNTIME:     "⚡",
};

const STAGE_LABEL: Record<string, string> = {
  REQUIREMENT: "Requirements",
  CODE:        "Code",
  DEPENDENCY:  "Dependencies",
  SECURITY:    "Security",
  TEST:        "Tests",
  RUNTIME:     "Runtime",
};

export default function ProvenanceGraphView({ graph }: { graph: ProvenanceGraph }) {
  return (
    <div className="prov-wrap card">
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
        <div className="section-title" style={{ margin: 0 }}>
          Evidence &amp; Provenance Chain
        </div>
        <span className={`badge ${graph.traceable ? "badge-pass" : "badge-fail"}`}>
          {graph.traceable ? "✓ TRACEABLE" : "✗ CHAIN BROKEN"}
        </span>
      </div>

      <div className="prov-chain">
        {graph.nodes.map((node, i) => {
          const isPass    = node.status === "PASS";
          const isFail    = node.status === "FAIL";

          return (
            <div key={i} className="prov-node-wrap">
              <div className={`prov-node ${isFail ? "pnode-fail" : isPass ? "pnode-pass" : "pnode-pending"}`}>
                <div className="pnode-icon">{STAGE_ICON[node.stage] ?? "🔍"}</div>
                <div className="pnode-label">{STAGE_LABEL[node.stage] ?? node.stage}</div>
                <div className={`pnode-status ${isFail ? "st-fail" : isPass ? "st-pass" : "st-pending"}`}>
                  {isFail ? "FAIL" : isPass ? "PASS" : node.status}
                </div>
                {node.findings_count > 0 && (
                  <div className="pnode-count">{node.findings_count} issue{node.findings_count !== 1 ? "s" : ""}</div>
                )}
                <div className={`badge ${node.scan_mode === "LIVE" ? "badge-live" : "badge-demo"}`} style={{ marginTop: 4, fontSize: 9 }}>
                  {node.scan_mode}
                </div>
              </div>
              {i < graph.nodes.length - 1 && (
                <div className="prov-arrow">→</div>
              )}
            </div>
          );
        })}
      </div>

      <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 10 }}>
        Traceable evidence chain from requirements to runtime. Each node records what was checked, findings, and scan mode.
      </div>
    </div>
  );
}
