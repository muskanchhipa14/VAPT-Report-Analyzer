from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime


class SourceCodeFindingResponse(BaseModel):
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
    created_at: datetime

    class Config:
        from_attributes = True


class SourceCodeAnalysisResponse(BaseModel):
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

    class Config:
        from_attributes = True


class SourceCodeAnalysisDetailResponse(SourceCodeAnalysisResponse):
    findings: List[SourceCodeFindingResponse] = []

    class Config:
        from_attributes = True


class SourceCodeScanUploadResponse(BaseModel):
    message: str
    analysis_id: int
    project_name: str
    filename: str
    files_scanned: int
    lines_scanned: int
    vulnerabilities_found: int
    severity_summary: Dict[str, int]
    findings: List[SourceCodeFindingResponse] = []
