from fastapi import FastAPI

from app.api import reports
from app.api import users
from app.api import auth
from app.api import vulnerability
from app.api import audit_log
from app.api import knowledge_base

from app.core.database import Base, engine

# Import all models
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.models.audit_log import AuditLog
from app.models.knowledge_base import KnowledgeBase

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="VAPT Backend API",
    version="1.0.0"
)

app.include_router(reports.router)
app.include_router(users.router)
app.include_router(auth.router)
app.include_router(vulnerability.router)
app.include_router(audit_log.router)
app.include_router(knowledge_base.router)


@app.get("/")
def home():
    return {
        "message": "VAPT Backend Running"
    }