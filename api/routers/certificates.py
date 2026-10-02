"""
GET /certificates/{cert_id}         — look up by CATO-... ID
GET /certificates/verify/{hash}     — verify a SHA-256 hash
GET /certificates                   — list recent certificates
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import get_db
from ..models_db import Certificate

router = APIRouter(prefix="/certificates", tags=["certificates"])


@router.get("")
def list_certificates(limit: int = 20, db: Session = Depends(get_db)):
    certs = db.query(Certificate).order_by(Certificate.issued_at.desc()).limit(limit).all()
    return {"certificates": [_out(c) for c in certs]}


@router.get("/verify/{cert_hash}")
def verify_certificate(cert_hash: str, db: Session = Depends(get_db)):
    cert = db.query(Certificate).filter(Certificate.cert_hash == cert_hash).first()
    if not cert:
        return {"verified": False, "cert_hash": cert_hash}
    return {
        "verified": True,
        "cert_id": cert.cert_id,
        "cert_hash": cert.cert_hash,
        "issued_at": cert.issued_at.isoformat(),
        "decision": cert.decision,
        "trust_score": cert.trust_score,
        "project_name": cert.project_name,
    }


@router.get("/{cert_id}")
def get_certificate(cert_id: str, db: Session = Depends(get_db)):
    cert = db.query(Certificate).filter(Certificate.cert_id == cert_id).first()
    if not cert:
        raise HTTPException(404, "Certificate not found")
    return _out(cert)


def _out(cert: Certificate) -> dict:
    return {
        "cert_id": cert.cert_id,
        "cert_hash": cert.cert_hash,
        "issued_at": cert.issued_at.isoformat(),
        "decision": cert.decision,
        "trust_score": cert.trust_score,
        "project_name": cert.project_name,
        "scan_id": cert.scan_id,
    }
