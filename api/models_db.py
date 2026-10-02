"""
ORM models — mapped to PostgreSQL tables.

projects      → one row per tracked project
scans         → one row per cato analyze run
scan_checks   → one row per check (6 per scan)
findings      → one row per finding (N per check)
certificates  → one row per issued trust certificate
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime,
    ForeignKey, Text, JSON,
)
from sqlalchemy.orm import relationship
from .db import Base


def _now():
    return datetime.now(timezone.utc)


def _uuid():
    return str(uuid.uuid4())


class Project(Base):
    __tablename__ = "projects"

    id         = Column(String, primary_key=True, default=_uuid)
    name       = Column(String, nullable=False)
    repo_url   = Column(String, nullable=True)
    created_at = Column(DateTime, default=_now)

    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id            = Column(String, primary_key=True, default=_uuid)
    project_id    = Column(String, ForeignKey("projects.id"), nullable=False)
    trigger       = Column(String, default="api")   # api | cli | github
    project_path  = Column(String, nullable=True)
    timestamp     = Column(DateTime, default=_now)
    decision      = Column(String, nullable=False)
    risk_level    = Column(String, nullable=False)
    trust_score   = Column(Integer, nullable=False)
    files_scanned = Column(Integer, default=0)
    total_ms      = Column(Float, default=0.0)
    policy_passed = Column(Boolean, default=False)

    project     = relationship("Project", back_populates="scans")
    checks      = relationship("ScanCheck", back_populates="scan", cascade="all, delete-orphan")
    certificate = relationship("Certificate", back_populates="scan", uselist=False, cascade="all, delete-orphan")


class ScanCheck(Base):
    __tablename__ = "scan_checks"

    id         = Column(String, primary_key=True, default=_uuid)
    scan_id    = Column(String, ForeignKey("scans.id"), nullable=False)
    check_name = Column(String, nullable=False)
    status     = Column(String, nullable=False)
    scan_mode  = Column(String, nullable=False)
    summary    = Column(Text, nullable=True)
    findings   = Column(JSON, default=list)   # serialised list of Finding dicts

    scan = relationship("Scan", back_populates="checks")


class Certificate(Base):
    __tablename__ = "certificates"

    id           = Column(String, primary_key=True, default=_uuid)
    scan_id      = Column(String, ForeignKey("scans.id"), nullable=False)
    cert_id      = Column(String, unique=True, nullable=False)
    cert_hash    = Column(String, unique=True, nullable=False)
    issued_at    = Column(DateTime, default=_now)
    decision     = Column(String, nullable=False)
    trust_score  = Column(Integer, nullable=False)
    project_name = Column(String, nullable=False)

    scan = relationship("Scan", back_populates="certificate")
