from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import sqlite3

from app.api import reports
from app.api import users
from app.api import auth
from app.api import vulnerability
from app.api import audit_log
from app.api import knowledge_base
from app.api import source_code
from app.api import analysis

from app.core.database import Base, engine, SessionLocal
from app.core.config import settings

# Import all models to register them with metadata
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.models.audit_log import AuditLog
from app.models.knowledge_base import KnowledgeBaseItem
from app.models.source_code import SourceCodeAnalysis, SourceCodeFinding

from app.services.knowledge_base import seed_knowledge_base

# Create DB tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title=settings.PROJECT_NAME)

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(reports.router)
app.include_router(users.router)
app.include_router(auth.router)
app.include_router(vulnerability.router)
app.include_router(audit_log.router)
app.include_router(knowledge_base.router)
app.include_router(source_code.router)
app.include_router(analysis.router)


def _ensure_sqlite_columns():
    """Guarantees SQLite table schema contains all newly added columns without crashing."""
    try:
        raw_db_path = settings.DATABASE_URL.replace("sqlite:///", "").replace("sqlite://", "")
        if os.path.exists(raw_db_path):
            conn = sqlite3.connect(raw_db_path)
            c = conn.cursor()
            
            # Check vulnerabilities table
            existing_vuln_cols = [r[1] for r in c.execute("PRAGMA table_info(vulnerabilities)").fetchall()]
            vuln_columns = [
                ("cve_id", "VARCHAR"),
                ("language", "VARCHAR"),
                ("framework", "VARCHAR"),
                ("evidence", "TEXT"),
                ("why_vulnerable", "TEXT"),
                ("ai_remediation", "TEXT"),
                ("secure_code", "TEXT"),
                ("implementation_steps", "TEXT"),
                ("verification_steps", "TEXT")
            ]
            for col_name, col_type in vuln_columns:
                if col_name not in existing_vuln_cols:
                    c.execute(f"ALTER TABLE vulnerabilities ADD COLUMN {col_name} {col_type}")

            # Check source_code_findings table
            existing_finding_cols = [r[1] for r in c.execute("PRAGMA table_info(source_code_findings)").fetchall()]
            finding_columns = [
                ("framework", "VARCHAR"),
                ("why_vulnerable", "TEXT"),
                ("ai_remediation", "TEXT"),
                ("secure_code", "TEXT"),
                ("implementation_steps", "TEXT"),
                ("verification_steps", "TEXT")
            ]
            for col_name, col_type in finding_columns:
                if col_name not in existing_finding_cols:
                    c.execute(f"ALTER TABLE source_code_findings ADD COLUMN {col_name} {col_type}")

            conn.commit()
            conn.close()
    except Exception as e:
        print(f"Warning verifying SQLite table columns: {e}")


import os

@app.on_event("startup")
def startup_event():
    _ensure_sqlite_columns()
    db = SessionLocal()
    try:
        seed_knowledge_base(db)
    except Exception as e:
        print(f"Error seeding knowledge base: {e}")
    finally:
        db.close()


@app.get("/")
def home():
    return {
        "message": "AI Vulnerability Detection & Remediation Engine Running",
        "docs": "/docs",
        "endpoints": [
            "/api/analyze/report",
            "/api/analyze/source-code",
            "/api/analyze/combined",
            "/api/remediation/generate",
            "/api/vulnerabilities"
        ]
    }