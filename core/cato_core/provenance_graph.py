"""
CATO — Evidence & Provenance Graph
====================================
Corresponds to the "Evidence & Provenance Graph" box in the architecture.
Traceable evidence chain: Requirements → Code → Dependencies → Security → Tests → Runtime

Each node in the graph records:
  - stage      : which phase (REQUIREMENT | CODE | DEPENDENCY | SECURITY | TEST | RUNTIME)
  - status     : PASS | FAIL | SKIP | PENDING
  - evidence   : list of findings/facts from that stage
  - timestamp  : when this stage was evaluated
"""

from datetime import datetime, timezone
from typing import List, Optional
from .models import CheckResult, CheckStatus


STAGES = ["REQUIREMENT", "CODE", "DEPENDENCY", "SECURITY", "TEST", "RUNTIME"]


class ProvenanceNode:
    def __init__(self, stage: str, status: str, summary: str, findings_count: int,
                 scan_mode: str = "LIVE"):
        self.stage          = stage
        self.status         = status
        self.summary        = summary
        self.findings_count = findings_count
        self.scan_mode      = scan_mode
        self.timestamp      = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "stage":          self.stage,
            "status":         self.status,
            "summary":        self.summary,
            "findings_count": self.findings_count,
            "scan_mode":      self.scan_mode,
            "timestamp":      self.timestamp,
        }


class ProvenanceGraph:
    def __init__(self):
        self.nodes: List[ProvenanceNode] = []
        self.traceable = True
        self.stages = STAGES

    def add_node(self, node: ProvenanceNode):
        self.nodes.append(node)
        if node.status == "FAIL":
            self.traceable = False

    def to_dict(self) -> dict:
        return {
            "nodes":     [n.to_dict() for n in self.nodes],
            "traceable": self.traceable,
            "stages":    STAGES,
        }


def build_provenance_graph(checks: List[CheckResult],
                           req_check: Optional[CheckResult] = None,
                           arch_check: Optional[CheckResult] = None) -> ProvenanceGraph:
    graph = ProvenanceGraph()

    # Stage 1: REQUIREMENT
    if req_check:
        graph.add_node(ProvenanceNode(
            stage="REQUIREMENT",
            status=req_check.status.value,
            summary=req_check.summary,
            findings_count=len(req_check.findings),
            scan_mode=req_check.scan_mode.value,
        ))
    else:
        graph.add_node(ProvenanceNode(
            stage="REQUIREMENT",
            status="SKIP",
            summary="No requirement context provided",
            findings_count=0,
            scan_mode="LIVE",
        ))

    # Stage 2: CODE (from SAST + Architecture)
    sast = next((c for c in checks if "sast" in c.check_name.lower() or "static" in c.check_name.lower()), None)
    arch_summary = arch_check.summary if arch_check else "Architecture check not run"
    arch_count   = len(arch_check.findings) if arch_check else 0
    arch_status  = arch_check.status.value if arch_check else "SKIP"

    code_count = (len(sast.findings) if sast else 0) + arch_count
    code_status = "FAIL" if (sast and sast.status == CheckStatus.FAIL) or (arch_check and arch_check.status == CheckStatus.FAIL) else "PASS"

    graph.add_node(ProvenanceNode(
        stage="CODE",
        status=code_status,
        summary=f"SAST: {sast.summary if sast else 'skipped'} | Arch: {arch_summary}",
        findings_count=code_count,
        scan_mode="LIVE",
    ))

    # Stage 3: DEPENDENCY
    dep = next((c for c in checks if "depend" in c.check_name.lower()), None)
    if dep:
        graph.add_node(ProvenanceNode(
            stage="DEPENDENCY",
            status=dep.status.value,
            summary=dep.summary,
            findings_count=len(dep.findings),
            scan_mode=dep.scan_mode.value,
        ))

    # Stage 4: SECURITY (from Secret Detection)
    sec = next((c for c in checks if "secret" in c.check_name.lower()), None)
    if sec:
        graph.add_node(ProvenanceNode(
            stage="SECURITY",
            status=sec.status.value,
            summary=sec.summary,
            findings_count=len(sec.findings),
            scan_mode=sec.scan_mode.value,
        ))

    # Stage 5: TEST
    test = next((c for c in checks if "test" in c.check_name.lower()), None)
    if test:
        graph.add_node(ProvenanceNode(
            stage="TEST",
            status=test.status.value,
            summary=test.summary,
            findings_count=0,
            scan_mode=test.scan_mode.value,
        ))

    # Stage 6: RUNTIME (future — placeholder)
    graph.add_node(ProvenanceNode(
        stage="RUNTIME",
        status="PENDING",
        summary="Runtime monitoring not yet active (future: eBPF + AppArmor)",
        findings_count=0,
        scan_mode="LIVE",
    ))

    return graph
