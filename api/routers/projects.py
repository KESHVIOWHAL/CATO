"""
POST /projects          — register a project
GET  /projects          — list all projects
GET  /projects/{id}     — get project detail
GET  /projects/{id}/history — scan history for a project
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional
import uuid

from ..db import get_db
from ..models_db import Project, Scan

router = APIRouter(prefix="/projects", tags=["projects"])


class ProjectCreate(BaseModel):
    name: str
    repo_url: Optional[str] = None


class ProjectOut(BaseModel):
    id: str
    name: str
    repo_url: Optional[str]
    created_at: str

    class Config:
        from_attributes = True


@router.post("", response_model=ProjectOut, status_code=201)
def create_project(body: ProjectCreate, db: Session = Depends(get_db)):
    project = Project(id=str(uuid.uuid4()), name=body.name, repo_url=body.repo_url)
    db.add(project)
    db.commit()
    db.refresh(project)
    return _to_out(project)


@router.get("", response_model=list[ProjectOut])
def list_projects(db: Session = Depends(get_db)):
    return [_to_out(p) for p in db.query(Project).order_by(Project.created_at.desc()).all()]


@router.get("/{project_id}", response_model=ProjectOut)
def get_project(project_id: str, db: Session = Depends(get_db)):
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    return _to_out(p)


@router.get("/{project_id}/history")
def project_history(project_id: str, db: Session = Depends(get_db)):
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    scans = db.query(Scan).filter(Scan.project_id == project_id)\
               .order_by(Scan.timestamp.desc()).limit(50).all()
    return {
        "project": _to_out(p),
        "scans": [
            {
                "id": s.id,
                "timestamp": s.timestamp.isoformat(),
                "decision": s.decision,
                "trust_score": s.trust_score,
                "risk_level": s.risk_level,
                "trigger": s.trigger,
            }
            for s in scans
        ],
    }


def _to_out(p: Project) -> dict:
    return {
        "id": p.id,
        "name": p.name,
        "repo_url": p.repo_url,
        "created_at": p.created_at.isoformat() if p.created_at else "",
    }
