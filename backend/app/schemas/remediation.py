from pydantic import BaseModel, ConfigDict
from typing import Optional, List
from datetime import datetime


class RemediationJobCreate(BaseModel):
    finding_id: Optional[int] = None
    vulnerability_id: Optional[int] = None
    analysis_id: Optional[int] = None
    code_snippet: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = 1
    language: Optional[str] = None
    framework: Optional[str] = None
    cwe_id: Optional[str] = None
    vulnerability_name: Optional[str] = None
    severity: Optional[str] = "Medium"
    max_attempts: Optional[int] = 5
    timeout_seconds: Optional[int] = 300


class RemediationAttemptResponse(BaseModel):
    id: int
    job_id: int
    attempt_number: int
    state: str
    patch_diff: Optional[str] = None
    proposed_code: Optional[str] = None
    modified_file_path: Optional[str] = None
    assumptions: Optional[str] = None
    potential_regressions: Optional[str] = None
    why_vulnerable: Optional[str] = None
    ai_explanation: Optional[str] = None
    validation_passed: bool = False
    syntax_check_passed: bool = False
    syntax_errors: Optional[str] = None
    regression_test_passed: bool = True
    test_output: Optional[str] = None
    before_findings: Optional[str] = None
    after_findings: Optional[str] = None
    new_findings_detected: Optional[str] = None
    status_message: Optional[str] = None
    created_at: datetime
    duration_ms: int = 0

    model_config = ConfigDict(from_attributes=True)


class RemediationJobResponse(BaseModel):
    id: int
    job_uuid: str
    analysis_id: Optional[int] = None
    finding_id: Optional[int] = None
    vulnerability_id: Optional[int] = None
    finding_fingerprint: Optional[str] = None
    cwe_id: str
    vulnerability_name: str
    severity: str
    file_path: Optional[str] = None
    line_number: int = 1
    target_language: Optional[str] = None
    target_framework: Optional[str] = None
    user_id: Optional[int] = None
    state: str
    current_attempt: int = 0
    max_attempts: int = 5
    timeout_seconds: int = 300
    original_code_snippet: Optional[str] = None
    latest_code_snippet: Optional[str] = None
    final_patch_diff: Optional[str] = None
    initial_findings_count: int = 1
    verified_fixed_count: int = 0
    remaining_findings_count: int = 1
    new_findings_count: int = 0
    failure_reason: Optional[str] = None
    verification_evidence: Optional[str] = None
    is_cancelled: bool = False
    is_rolled_back: bool = False
    created_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime] = None
    attempts: List[RemediationAttemptResponse] = []

    model_config = ConfigDict(from_attributes=True)
