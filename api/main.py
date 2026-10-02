"""
CATO MVP API
────────────
Built on cato_core — the API is a persistence + HTTP layer only.
All security logic lives in cato_core.engine.

Endpoints:
  POST /projects
  GET  /projects
  GET  /projects/{id}
  GET  /projects/{id}/history

  POST /scans           (local path)
  POST /scans/upload    (ZIP upload)
  GET  /scans/{id}
  GET  /scans/{id}/findings
  GET  /scans/{id}/certificate

  GET  /certificates
  GET  /certificates/{cert_id}
  GET  /certificates/verify/{hash}

  GET  /health
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .db import Base, engine
from .routers import projects, scans, certificates

# Create all tables on startup (migrations handled by Alembic in production)
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="CATO — Context-Aware Trust Orchestrator",
    version="0.2.0",
    description="Developer security and trust tool. Analyzes code, produces APPROVE/REVIEW/BLOCK decisions.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(projects.router)
app.include_router(scans.router)
app.include_router(certificates.router)


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok", "version": "0.2.0"}
