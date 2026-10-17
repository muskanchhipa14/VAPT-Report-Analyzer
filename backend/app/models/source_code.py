from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Boolean
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
    framework = Column(String, nullable=True)
    why_vulnerable = Column(Text, nullable=True)
    ai_remediation = Column(Text, nullable=True)
    secure_code = Column(Text, nullable=True)
    implementation_steps = Column(Text, nullable=True)
    verification_steps = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    analysis = relationship("SourceCodeAnalysis", back_populates="findings")


class RemediationJob(Base):
    __tablename__ = "remediation_jobs"

    id = Column(Integer, primary_key=True, index=True)
    job_uuid = Column(String, unique=True, index=True, nullable=False)
    analysis_id = Column(Integer, ForeignKey("source_code_analyses.id", ondelete="SET NULL"), nullable=True, index=True)
    finding_id = Column(Integer, ForeignKey("source_code_findings.id", ondelete="SET NULL"), nullable=True, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id", ondelete="SET NULL"), nullable=True, index=True)
    finding_fingerprint = Column(String, index=True, nullable=True)
    cwe_id = Column(String, nullable=False)
    vulnerability_name = Column(String, nullable=False)
    severity = Column(String, nullable=False, default="Medium")
    file_path = Column(String, nullable=True)
    line_number = Column(Integer, default=1)
    target_language = Column(String, nullable=True)
    target_framework = Column(String, nullable=True)
    user_id = Column(Integer, index=True, nullable=True)
    state = Column(String, default="QUEUED", index=True, nullable=False)
    current_attempt = Column(Integer, default=0)
    max_attempts = Column(Integer, default=5)
    timeout_seconds = Column(Integer, default=300)
    workspace_path = Column(String, nullable=True)
    original_code_snippet = Column(Text, nullable=True)
    latest_code_snippet = Column(Text, nullable=True)
    final_patch_diff = Column(Text, nullable=True)
    initial_findings_count = Column(Integer, default=1)
    verified_fixed_count = Column(Integer, default=0)
    remaining_findings_count = Column(Integer, default=1)
    new_findings_count = Column(Integer, default=0)
    failure_reason = Column(Text, nullable=True)
    verification_evidence = Column(Text, nullable=True)
    is_cancelled = Column(Boolean, default=False)
    is_rolled_back = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    attempts = relationship(
        "RemediationAttempt",
        back_populates="job",
        cascade="all, delete-orphan",
        order_by="RemediationAttempt.attempt_number"
    )


class RemediationAttempt(Base):
    __tablename__ = "remediation_attempts"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, ForeignKey("remediation_jobs.id", ondelete="CASCADE"), index=True, nullable=False)
    attempt_number = Column(Integer, nullable=False)
    state = Column(String, nullable=False)
    patch_diff = Column(Text, nullable=True)
    proposed_code = Column(Text, nullable=True)
    modified_file_path = Column(String, nullable=True)
    assumptions = Column(Text, nullable=True)
    potential_regressions = Column(Text, nullable=True)
    why_vulnerable = Column(Text, nullable=True)
    ai_explanation = Column(Text, nullable=True)
    validation_passed = Column(Boolean, default=False)
    syntax_check_passed = Column(Boolean, default=False)
    syntax_errors = Column(Text, nullable=True)
    regression_test_passed = Column(Boolean, default=True)
    test_output = Column(Text, nullable=True)
    before_findings = Column(Text, nullable=True)
    after_findings = Column(Text, nullable=True)
    new_findings_detected = Column(Text, nullable=True)
    status_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    duration_ms = Column(Integer, default=0)

    job = relationship("RemediationJob", back_populates="attempts")

