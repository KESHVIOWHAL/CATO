import { useState } from "react";
import Dashboard from "./components/Dashboard.tsx";
import CertificateView from "./components/CertificateView.tsx";
import BlockchainView from "./components/BlockchainView.tsx";
import RoadmapView from "./components/RoadmapView.tsx";
import ArchView from "./components/ArchView.tsx";
import AIProtectionPanel from "./components/AIProtectionPanel.tsx";
import AIvsCATO from "./components/AIvsCATO.tsx";
import CostView from "./components/CostView.tsx";
import LiveAnalyzer from "./components/LiveAnalyzer.tsx";
import ResearchView from "./components/ResearchView.tsx";
import EvalSuite from "./components/EvalSuite.tsx";
import TimingView from "./components/TimingView.tsx";
import type { AnalysisResult } from "./api.ts";
import "./App.css";

type View = "dashboard" | "live" | "eval" | "timing" | "protection" | "compare" | "certificate" | "blockchain" | "arch" | "research" | "cost" | "roadmap";

export default function App() {
  const [view, setView]     = useState<View>("dashboard");
  const [result, setResult] = useState<AnalysisResult | null>(null);

  const nav = (v: View, label: string, show = true) =>
    show ? (
      <button key={v} className={view === v ? "active" : ""} onClick={() => setView(v)}>
        {label}
      </button>
    ) : null;

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="topbar-brand">
          <img src="/cato-logo.png" alt="CATO" className="brand-logo" />
          <span className="brand-name">CATO</span>
          <span className="brand-sub">Context-Aware Trust Orchestrator</span>
        </div>
        <nav className="topbar-nav">
          {nav("dashboard",   "Dashboard")}
          {nav("live",        "Paste Code")}
          {nav("eval",        "Eval Suite")}
          {nav("timing",      "⏱ Timing")}
          {nav("protection",  "AI Protection")}
          {nav("compare",     "AI vs CATO")}
          {nav("certificate", "Certificate", !!result?.certificate_id)}
          {nav("blockchain",  "Blockchain")}
          {nav("arch",        "Architecture")}
          {nav("research",    "Research")}
          {nav("cost",        "Cost & Business")}
          {nav("roadmap",     "Roadmap")}
        </nav>
        <div className="topbar-tag">
          <span className="tag-sih">SIH 2026</span>
          <span className="tag-team">ThinkTank</span>
        </div>
      </header>

      <main className="main-content">
        {view === "dashboard"   && <Dashboard result={result} setResult={setResult} onViewCert={() => setView("certificate")} />}
        {view === "live"        && <LiveAnalyzer />}
        {view === "eval"        && <EvalSuite />}
        {view === "timing"      && <TimingView />}
        {view === "protection"  && <AIProtectionPanel />}
        {view === "compare"     && <AIvsCATO />}
        {view === "certificate" && result?.certificate_id && <CertificateView certId={result.certificate_id} />}
        {view === "blockchain"  && <BlockchainView />}
        {view === "arch"        && <ArchView />}
        {view === "research"    && <ResearchView />}
        {view === "cost"        && <CostView />}
        {view === "roadmap"     && <RoadmapView />}
      </main>
    </div>
  );
}
