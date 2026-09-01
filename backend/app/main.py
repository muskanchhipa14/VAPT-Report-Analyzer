from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import reports
from app.api import users
from app.api import auth
from app.api import vulnerability
from app.api import audit_log
from app.api import knowledge_base
from app.api import evaluation

from app.core.database import Base, engine

# Import all models
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.models.audit_log import AuditLog
from app.models.knowledge_base import KnowledgeBase
from app.models.report import Report

app = FastAPI(
    title="Intelligent VAPT Report Analysis & Remediation System API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)

app.include_router(reports.router)
app.include_router(users.router)
app.include_router(auth.router)
app.include_router(vulnerability.router)
app.include_router(audit_log.router)
app.include_router(knowledge_base.router)
app.include_router(evaluation.router)


@app.get("/")
def home():
    return {
        "message": "VAPT Backend Running"
    }