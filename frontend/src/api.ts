const BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

// ── Core types ────────────────────────────────────────────────────────────────

export interface Finding {
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  description: string;
  location?: string;
  remediation?: string;
}

export interface CheckResult {
  check_name: string;
  status: "PASS" | "FAIL" | "SKIP";
  scan_mode: "LIVE" | "DEMO";
  findings: Finding[];
  summary: string;
}

export interface PolicyResult {
  passed: boolean;
  reasons: string[];
}

export interface ProvenanceNode {
  stage: string;
  status: string;
  summary: string;
  findings_count: number;
  scan_mode: string;
  timestamp: string;
}

export interface ProvenanceGraph {
  nodes: ProvenanceNode[];
  traceable: boolean;
  stages: string[];
}

export interface AIProtectionFinding {
  category: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  title: string;
  description: string;
  action: "BLOCK" | "SANITIZE" | "WARN";
  line: number;
}

export interface AIProtectionResult {
  findings: AIProtectionFinding[];
  blocked: boolean;
  routing: string;
  summary: string;
}

export interface Recommendation {
  priority: number;
  category: string;
  title: string;
  what: string;
  fix: string;
  example?: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  location?: string;
}

export interface AnalysisResult {
  project_name: string;
  project_path: string;
  timestamp: string;
  checks: CheckResult[];
  decision: "APPROVE" | "REVIEW" | "BLOCK";
  risk_level: string;
  trust_score: number;
  decision_reasons: string[];
  policy: PolicyResult;
  recommendations: Recommendation[];
  provenance?: ProvenanceGraph;
  ai_protection?: AIProtectionResult;
  files_scanned: number;
  certificate_id?: string;
  certificate_hash?: string;
  blockchain_tx?: string;
  blockchain_status?: string;
}

export interface TrustCertificate {
  certificate_id: string;
  project_name: string;
  timestamp: string;
  decision: string;
  risk_level: string;
  trust_score: number;
  checks: CheckResult[];
  findings_summary: string[];
  recommendations_summary: string[];
  policy_passed: boolean;
  provenance?: ProvenanceGraph;
  certificate_hash: string;
  blockchain_tx?: string;
  blockchain_status: string;
}

export interface BlockchainBlock {
  index: number;
  timestamp: string;
  certificate_hash: string;
  certificate_id: string;
  previous_hash: string;
  block_hash: string;
}

export interface ScannerStatus {
  gitleaks: boolean;
  semgrep: boolean;
  osv_scanner_binary: boolean;
  osv_api_network: boolean;
  pytest: boolean;
  builtin_secret_scanner: boolean;
  builtin_sast: boolean;
}

// ── Feature 1: Comparison types ───────────────────────────────────────────────

export interface CompareTableRow {
  metric: string;
  direct: string;
  cato: string;
}

export interface DirectResult {
  label: string;
  action: string;
  action_label: string;
  secrets_exposed: string[];
  simulated_response: string;
  warning: string;
  prompt_inspected: boolean;
}

export interface CatoResult {
  label: string;
  action: string;
  action_label: string;
  findings: AIProtectionFinding[];
  sanitized_prompt: string;
  routing: string;
  latency: { stages: Record<string, number>; total_ms: number };
}

export interface CompareResult {
  prompt_size_kb: number;
  ai_model: string;
  direct: DirectResult;
  cato: CatoResult;
  comparison_table: CompareTableRow[];
  key_message: string;
}

// ── Feature 2: Benchmark types ────────────────────────────────────────────────

export interface BenchmarkResult {
  runs: number;
  prompt_size_kb: number;
  min_ms: number;
  max_ms: number;
  avg_ms: number;
  median_ms: number;
  stdev_ms: number;
  stage_averages_ms: Record<string, number>;
  all_times_ms: number[];
}

// ── API functions ─────────────────────────────────────────────────────────────

export async function analyzeProject(projectName: string, projectPath: string, projectContext = ""): Promise<AnalysisResult> {
  const res = await fetch(`${BASE}/analyze`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ project_name: projectName, project_path: projectPath, project_context: projectContext }),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json() as Promise<AnalysisResult>;
}

export async function uploadAndAnalyze(projectName: string, sourceZip: File, policyJson: string, architectureNotes: string): Promise<AnalysisResult> {
  const form = new FormData();
  form.append("project_name", projectName);
  form.append("source_zip", sourceZip);
  form.append("policy_json", policyJson);
  form.append("architecture_notes", architectureNotes);
  const res = await fetch(`${BASE}/upload`, { method: "POST", body: form });
  if (!res.ok) throw new Error(await res.text());
  return res.json() as Promise<AnalysisResult>;
}

export async function listProjects(): Promise<{ projects: { id: string; name: string; path: string; description: string }[] }> {
  const res = await fetch(`${BASE}/projects`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function getScannerStatus(): Promise<ScannerStatus> {
  const res = await fetch(`${BASE}/scanner-status`);
  if (!res.ok) throw new Error(await res.text());
  return res.json() as Promise<ScannerStatus>;
}

export async function checkAIProtection(text: string): Promise<AIProtectionResult> {
  const res = await fetch(`${BASE}/protect`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text }),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json() as Promise<AIProtectionResult>;
}

export async function getCertificate(certId: string): Promise<TrustCertificate> {
  const res = await fetch(`${BASE}/certificate/${certId}`);
  if (!res.ok) throw new Error(await res.text());
  return res.json() as Promise<TrustCertificate>;
}

export async function verifyCertificate(hash: string): Promise<{ verified: boolean; block_index?: number; timestamp?: string }> {
  const res = await fetch(`${BASE}/verify/${hash}`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function getChain(): Promise<{ chain: BlockchainBlock[]; length: number; valid: boolean; mode: string }> {
  const res = await fetch(`${BASE}/blockchain/chain`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function compareAIvsCato(prompt: string, aiModel: string): Promise<CompareResult> {
  const res = await fetch(`${BASE}/compare`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ prompt, ai_model: aiModel }),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json() as Promise<CompareResult>;
}

export async function getDemoPrompt(): Promise<{ prompt: string }> {
  const res = await fetch(`${BASE}/compare/demo-prompt`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function runBenchmark(prompt: string, runs: number): Promise<BenchmarkResult> {
  const res = await fetch(`${BASE}/benchmark`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ prompt, runs }),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json() as Promise<BenchmarkResult>;
}

export async function analyzeInline(payload: {
  code: string;
  language?: string;
  filename?: string;
  requirements?: string;
  context?: string;
  policy?: Record<string, string> | null;
}): Promise<InlineResult> {
  const res = await fetch(`${BASE}/analyze-inline`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json() as Promise<InlineResult>;
}

export interface WorkflowStep {
  name: string;
  icon: string;
  status: "PASS" | "FAIL" | "SKIP";
  summary: string;
  findings: number;
  ms: number;
}

export interface InlineFinding {
  check: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  description: string;
  location?: string;
  remediation?: string;
}

export interface InlineResult {
  decision: "APPROVE" | "REVIEW" | "BLOCK";
  risk_level: string;
  trust_score: number;
  workflow_steps: WorkflowStep[];
  all_findings: InlineFinding[];
  decision_reasons: string[];
  policy_passed: boolean;
  recommendations: Array<{
    priority: number;
    category: string;
    title: string;
    what: string;
    fix: string;
    severity: string;
    location?: string;
  }>;
  provenance: ProvenanceGraph;
  files_scanned: number;
  lines_scanned: number;
}

export async function runSizeBenchmark(): Promise<Record<string, BenchmarkResult>> {
  const res = await fetch(`${BASE}/benchmark/sizes`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export interface EvalResult {
  id: string;
  name: string;
  files: number;
  findings: number;
  critical: number;
  high: number;
  medium: number;
  tests: string;
  decision: string;
  trust_score: number;
  elapsed_s: number;
  cert_id?: string;
  error?: string;
}

export async function runEvaluationSuite(): Promise<{ results: EvalResult[] }> {
  const res = await fetch(`${BASE}/evaluate-suite`, { method: "POST" });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export interface PreAITiming {
  layer: string;
  description: string;
  results: Record<string, {
    prompt_size_kb: number;
    avg_ms: number;
    median_ms: number;
    min_ms: number;
    max_ms: number;
    stage_avg_ms: Record<string, number>;
  }>;
}

export interface PostAITiming {
  layer: string;
  description: string;
  note: string;
  results: Array<{
    project: string;
    files_scanned: number;
    total_ms: number;
    total_s: number;
    stage_ms: Record<string, number>;
    decision: string;
    error?: string;
  }>;
}

export async function getPreAITiming(): Promise<PreAITiming> {
  const res = await fetch(`${BASE}/timing/pre-ai`);
  if (!res.ok) throw new Error(await res.text());
  return res.json() as Promise<PreAITiming>;
}

export async function getPostAITiming(): Promise<PostAITiming> {
  const res = await fetch(`${BASE}/timing/post-ai`);
  if (!res.ok) throw new Error(await res.text());
  return res.json() as Promise<PostAITiming>;
}
