from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any


@dataclass
class ScanFinding:
    file_name: str
    line_number: int
    language: str
    vulnerability_name: str
    cwe_id: str
    severity: str
    confidence: str  # "High", "Medium", "Low"
    matched_code: str
    code_snippet: str
    suggested_fix: Optional[str] = None
    description: Optional[str] = None
    remediation: Optional[str] = None
    recommendation: Optional[str] = None
    owasp_category: Optional[str] = None


@dataclass
class FileScanResult:
    file_path: str
    language: str
    line_count: int
    findings: List[ScanFinding] = field(default_factory=list)


@dataclass
class ScanSummary:
    files_scanned: int = 0
    lines_scanned: int = 0
    vulnerabilities_found: int = 0
    severity_counts: Dict[str, int] = field(default_factory=lambda: {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0
    })
    language_counts: Dict[str, int] = field(default_factory=dict)
    findings: List[ScanFinding] = field(default_factory=list)
