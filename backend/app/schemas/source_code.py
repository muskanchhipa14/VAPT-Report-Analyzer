from pydantic import BaseModel, ConfigDict
from typing import Optional, List, Dict
from datetime import datetime


class SourceCodeFindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    analysis_id: int
    file_name: str
    line_number: int
    language: str
    vulnerability_name: str
    cwe_id: str
    severity: str
    confidence: str
    matched_code: Optional[str] = None
    code_snippet: Optional[str] = None
    suggested_fix: Optional[str] = None
    description: Optional[str] = None
    remediation: Optional[str] = None
    recommendation: Optional[str] = None
    owasp_category: Optional[str] = None
    framework: Optional[str] = None
    why_vulnerable: Optional[str] = None
    ai_remediation: Optional[str] = None
    secure_code: Optional[str] = None
    implementation_steps: Optional[str] = None
    verification_steps: Optional[str] = None
    created_at: datetime


class SourceCodeAnalysisResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_name: str
    filename: str
    status: str
    files_scanned: int
    lines_scanned: int
    vulnerabilities_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    user_id: Optional[int] = None
    created_at: datetime


class SourceCodeAnalysisDetailResponse(SourceCodeAnalysisResponse):
    model_config = ConfigDict(from_attributes=True)

    findings: List[SourceCodeFindingResponse] = []


class SourceCodeScanUploadResponse(BaseModel):
    message: str
    analysis_id: int
    project_name: str
    filename: str
    files_scanned: int
    lines_scanned: int
    vulnerabilities_found: int
    severity_summary: Dict[str, int]
    findings: List[SourceCodeFindingResponse]
