from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import reports
from app.api import users
from app.api import auth
from app.api import vulnerability
from app.api import audit_log
from app.api import knowledge_base
from app.api import source_code

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


@app.on_event("startup")
def startup_event():
    db = SessionLocal()
    try:
        seed_knowledge_base(db)
    except Exception as e:
        print(f"Error seeding knowledge base: {e}")
    finally:
        db.close()


@app.get("/")
def home():
    return {"message": "VAPT Backend Running"}