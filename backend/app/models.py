from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from enum import Enum


class CheckStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Decision(str, Enum):
    APPROVE = "APPROVE"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class ScanMode(str, Enum):
    LIVE = "LIVE"
    DEMO = "DEMO"


class Finding(BaseModel):
    title: str
    severity: Severity
    description: str
    location: Optional[str] = None
    remediation: Optional[str] = None


class Recommendation(BaseModel):
    priority: int
    category: str
    title: str
    what: str
    fix: str
    example: Optional[str] = None
    severity: Severity
    location: Optional[str] = None


class CheckResult(BaseModel):
    check_name: str
    status: CheckStatus
    scan_mode: ScanMode
    findings: List[Finding] = []
    summary: str


class AnalysisRequest(BaseModel):
    project_name: str
    project_path: str
    project_context: Optional[str] = ""     # architecture notes / requirement context


class ProtectionFindingModel(BaseModel):
    category: str
    severity: Severity
    title: str
    description: str
    action: str                             # BLOCK | SANITIZE | WARN
    line: int = 0


class AIProtectionResult(BaseModel):
    findings: List[ProtectionFindingModel] = []
    blocked: bool = False
    routing: str = "APPROVED_EXT_AI"
    summary: str = ""


class ProvenanceNodeModel(BaseModel):
    stage: str
    status: str
    summary: str
    findings_count: int
    scan_mode: str
    timestamp: str


class ProvenanceGraphModel(BaseModel):
    nodes: List[ProvenanceNodeModel]
    traceable: bool
    stages: List[str]


class PolicyResult(BaseModel):
    passed: bool
    reasons: List[str]


class AnalysisResult(BaseModel):
    project_name: str
    project_path: str
    timestamp: str
    # All 6 check categories
    checks: List[CheckResult]
    # Decision
    decision: Decision
    risk_level: str
    trust_score: int
    decision_reasons: List[str]
    policy: PolicyResult
    recommendations: List[Recommendation] = []
    # Evidence & Provenance
    provenance: Optional[ProvenanceGraphModel] = None
    # AI Protection layer (populated when input_text is provided)
    ai_protection: Optional[AIProtectionResult] = None
    # Meta
    files_scanned: int = 0
    post_ai_stage_ms: dict = {}
    post_ai_total_ms: float = 0.0
    certificate_id: Optional[str] = None
    certificate_hash: Optional[str] = None
    blockchain_tx: Optional[str] = None
    blockchain_status: Optional[str] = None


class TrustCertificate(BaseModel):
    certificate_id: str
    project_name: str
    timestamp: str
    decision: Decision
    risk_level: str
    trust_score: int
    checks: List[CheckResult]
    findings_summary: List[str]
    recommendations_summary: List[str]
    policy_passed: bool
    provenance: Optional[ProvenanceGraphModel] = None
    certificate_hash: str
    blockchain_tx: Optional[str] = None
    blockchain_status: str
