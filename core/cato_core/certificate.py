import hashlib
import json
import uuid
from datetime import datetime, timezone
from .models import AnalysisResult, TrustCertificate


def generate_certificate(result: AnalysisResult) -> TrustCertificate:
    cert_id = f"CATO-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"

    findings_summary = []
    for check in result.checks:
        for f in check.findings:
            findings_summary.append(f"[{f.severity}] {f.title} — {f.description[:100]}")

    recommendations_summary = [
        f"#{r.priority} [{r.severity}] {r.title}: {r.fix[:120]}"
        for r in result.recommendations
    ]

    cert_data = {
        "certificate_id":       cert_id,
        "project_name":         result.project_name,
        "timestamp":            result.timestamp,
        "decision":             result.decision,
        "risk_level":           result.risk_level,
        "trust_score":          result.trust_score,
        "findings_summary":     findings_summary,
        "recommendations":      recommendations_summary,
        "policy_passed":        result.policy.passed,
        "provenance_traceable": result.provenance.traceable if result.provenance else None,
        "checks": [
            {"name": c.check_name, "status": c.status, "findings_count": len(c.findings)}
            for c in result.checks
        ],
    }

    canonical = json.dumps(cert_data, sort_keys=True, ensure_ascii=True)
    cert_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    return TrustCertificate(
        certificate_id=cert_id,
        project_name=result.project_name,
        timestamp=result.timestamp,
        decision=result.decision,
        risk_level=result.risk_level,
        trust_score=result.trust_score,
        checks=result.checks,
        findings_summary=findings_summary,
        recommendations_summary=recommendations_summary,
        policy_passed=result.policy.passed,
        provenance=result.provenance,
        certificate_hash=cert_hash,
        blockchain_tx=result.blockchain_tx,
        blockchain_status=result.blockchain_status or "PENDING",
    )
