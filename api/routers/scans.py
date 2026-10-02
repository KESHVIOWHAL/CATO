"""
POST /scans                     — run a scan on an uploaded ZIP or local path
GET  /scans/{id}                — get full scan result
GET  /scans/{id}/findings       — findings only
GET  /scans/{id}/certificate    — certificate for this scan
"""

import shutil
import tempfile
import uuid
import zipfile
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel
from sqlalchemy.orm import Session

from cato_core.engine import run_analysis

from ..db import get_db
from ..models_db import Certificate, Project, Scan, ScanCheck

router = APIRouter(prefix="/scans", tags=["scans"])


# ── Request / response schemas ────────────────────────────────────────────────

class ScanRequest(BaseModel):
    project_name: str
    project_path: str                    # local path on server
    project_id: Optional[str] = None
    project_context: Optional[str] = ""
    trigger: Optional[str] = "api"


class ScanSummary(BaseModel):
    id: str
    project_name: str
    timestamp: str
    decision: str
    risk_level: str
    trust_score: int
    files_scanned: int
    trigger: str
    certificate_id: Optional[str] = None
    cert_hash: Optional[str] = None


# ── POST /scans  (path-based) ─────────────────────────────────────────────────

@router.post("", response_model=ScanSummary, status_code=201)
def create_scan(body: ScanRequest, db: Session = Depends(get_db)):
    project_path = Path(body.project_path)
    if not project_path.exists():
        raise HTTPException(400, f"Path does not exist: {body.project_path}")

    result = run_analysis(project_path, body.project_name, body.project_context or "")
    return _persist(result, body.trigger or "api", body.project_id, db)


# ── POST /scans/upload  (ZIP upload) ─────────────────────────────────────────

@router.post("/upload", response_model=ScanSummary, status_code=201)
def upload_scan(
    project_name: str = Form(...),
    source_zip: UploadFile = File(...),
    policy_json: str = Form("{}"),
    project_context: str = Form(""),
    project_id: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    tmp = Path(tempfile.mkdtemp())
    try:
        zip_path = tmp / "upload.zip"
        with zip_path.open("wb") as f:
            shutil.copyfileobj(source_zip.file, f)

        extract_dir = tmp / "project"
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(extract_dir)

        # Write policy if provided
        import json
        try:
            policy = json.loads(policy_json)
            if policy:
                (extract_dir / "cato-policy.json").write_text(json.dumps(policy))
        except Exception:
            pass

        result = run_analysis(extract_dir, project_name, project_context)
        return _persist(result, "api", project_id, db)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ── GET /scans/{id} ───────────────────────────────────────────────────────────

@router.get("/{scan_id}")
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    return _scan_detail(scan)


# ── GET /scans/{id}/findings ──────────────────────────────────────────────────

@router.get("/{scan_id}/findings")
def get_findings(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    findings = []
    for check in scan.checks:
        for f in (check.findings or []):
            findings.append({**f, "check_name": check.check_name})
    return {"scan_id": scan_id, "total": len(findings), "findings": findings}


# ── GET /scans/{id}/certificate ───────────────────────────────────────────────

@router.get("/{scan_id}/certificate")
def get_scan_certificate(scan_id: str, db: Session = Depends(get_db)):
    cert = db.query(Certificate).filter(Certificate.scan_id == scan_id).first()
    if not cert:
        raise HTTPException(404, "Certificate not found for this scan")
    return {
        "cert_id": cert.cert_id,
        "cert_hash": cert.cert_hash,
        "issued_at": cert.issued_at.isoformat(),
        "decision": cert.decision,
        "trust_score": cert.trust_score,
        "project_name": cert.project_name,
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _persist(result, trigger: str, project_id: Optional[str], db: Session) -> dict:
    """Save AnalysisResult to DB and return ScanSummary."""

    # Auto-create project if none given
    if not project_id:
        proj = Project(id=str(uuid.uuid4()), name=result.project_name)
        db.add(proj)
        db.flush()
        project_id = proj.id

    scan_id = str(uuid.uuid4())
    scan = Scan(
        id=scan_id,
        project_id=project_id,
        trigger=trigger,
        project_path=result.project_path,
        decision=result.decision.value,
        risk_level=result.risk_level,
        trust_score=result.trust_score,
        files_scanned=result.files_scanned,
        total_ms=result.post_ai_total_ms,
        policy_passed=result.policy.passed,
    )
    db.add(scan)

    for check in result.checks:
        db.add(ScanCheck(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            check_name=check.check_name,
            status=check.status.value,
            scan_mode=check.scan_mode.value,
            summary=check.summary,
            findings=[f.model_dump() for f in check.findings],
        ))

    cert_row = Certificate(
        id=str(uuid.uuid4()),
        scan_id=scan_id,
        cert_id=result.certificate_id or "",
        cert_hash=result.certificate_hash or "",
        decision=result.decision.value,
        trust_score=result.trust_score,
        project_name=result.project_name,
    )
    db.add(cert_row)
    db.commit()

    return {
        "id": scan_id,
        "project_name": result.project_name,
        "timestamp": scan.timestamp.isoformat(),
        "decision": result.decision.value,
        "risk_level": result.risk_level,
        "trust_score": result.trust_score,
        "files_scanned": result.files_scanned,
        "trigger": trigger,
        "certificate_id": result.certificate_id,
        "cert_hash": result.certificate_hash,
    }


def _scan_detail(scan: Scan) -> dict:
    cert = scan.certificate
    return {
        "id": scan.id,
        "project_name": scan.project.name if scan.project else "",
        "project_path": scan.project_path,
        "timestamp": scan.timestamp.isoformat(),
        "decision": scan.decision,
        "risk_level": scan.risk_level,
        "trust_score": scan.trust_score,
        "files_scanned": scan.files_scanned,
        "total_ms": scan.total_ms,
        "policy_passed": scan.policy_passed,
        "trigger": scan.trigger,
        "checks": [
            {
                "check_name": c.check_name,
                "status": c.status,
                "scan_mode": c.scan_mode,
                "summary": c.summary,
                "findings": c.findings or [],
            }
            for c in scan.checks
        ],
        "certificate": {
            "cert_id": cert.cert_id,
            "cert_hash": cert.cert_hash,
            "issued_at": cert.issued_at.isoformat(),
        } if cert else None,
    }
