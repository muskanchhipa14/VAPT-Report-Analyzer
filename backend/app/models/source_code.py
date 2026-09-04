from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.database import Base


class SourceCodeAnalysis(Base):
    __tablename__ = "source_code_analyses"

    id = Column(Integer, primary_key=True, index=True)
    project_name = Column(String, nullable=False)
    filename = Column(String, nullable=False)
    status = Column(String, default="Completed")
    files_scanned = Column(Integer, default=0)
    lines_scanned = Column(Integer, default=0)
    vulnerabilities_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    user_id = Column(Integer, index=True, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    findings = relationship(
        "SourceCodeFinding",
        back_populates="analysis",
        cascade="all, delete-orphan"
    )


class SourceCodeFinding(Base):
    __tablename__ = "source_code_findings"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("source_code_analyses.id"), index=True, nullable=False)
    file_name = Column(String, nullable=False)
    line_number = Column(Integer, nullable=False, default=1)
    language = Column(String, nullable=False)
    vulnerability_name = Column(String, nullable=False)
    cwe_id = Column(String, nullable=False)
    severity = Column(String, nullable=False, default="Medium")
    confidence = Column(String, nullable=False, default="Medium")
    matched_code = Column(Text, nullable=True)
    code_snippet = Column(Text, nullable=True)
    suggested_fix = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    owasp_category = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    analysis = relationship("SourceCodeAnalysis", back_populates="findings")
