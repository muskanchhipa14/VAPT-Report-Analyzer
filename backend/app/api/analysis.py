import os
import tempfile
import uuid
import json
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import get_current_user_optional, get_current_user
from app.models.user import User
from app.models.report import Report
from app.models.vulnerability import Vulnerability
from app.schemas.vulnerability import VulnerabilityResponse
from app.services import report_service, vulnerability_service, source_code_service
from app.services.pdf_parser import parse_vapt_pdf, parse_vapt_docx, parse_vapt_image, parse_vapt_text
from app.services.ai_remediation_service import generate_remediation
from app.services.correlation_service import correlate_report_and_code
from app.source_scanner.scanner import scan_single_file_content
from app.source_scanner.language_detector import detect_language_and_context

router = APIRouter(
    prefix="/api",
    tags=["AI Vulnerability & Remediation Engine"]
)

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

REPORT_EXTENSIONS = {
    ".pdf", ".docx", ".txt", ".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tiff", ".svg"
}

SOURCE_CODE_EXTENSIONS = {
    ".py", ".pyw", ".java", ".cpp", ".cc", ".cxx", ".c", ".h", ".hpp",
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
    ".php", ".phtml", ".cs", ".go", ".rb", ".zip"
}


class RemediationGenerateRequest(BaseModel):
    vulnerability: str
    cwe_id: str
    severity: str = "Medium"
    language: Optional[str] = None
    framework: Optional[str] = None
    database_or_lib: Optional[str] = None
    file_name: Optional[str] = None
    line_number: Optional[int] = None
    vulnerable_code: Optional[str] = None
    description: Optional[str] = None
    kb_remediation: Optional[str] = None


@router.post("/analyze/report")
async def analyze_report(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """
    Flow 1: VAPT Report Upload
    Parses PDF, DOCX, TXT, or Image report, extracts findings, retrieves KB context,
    and synthesizes language-specific AI remediations for each vulnerability found.
    """
    filename = file.filename or "vapt_report.pdf"
    ext = os.path.splitext(filename.lower())[1]

    if ext not in REPORT_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file format '{ext}'. Supported formats: PDF, DOCX, TXT, PNG, JPG, JPEG, WEBP."
        )

    temp_path = os.path.join(tempfile.gettempdir(), f"report_{uuid.uuid4().hex}{ext}")

    try:
        content_bytes = await file.read()
        with open(temp_path, "wb") as f:
            f.write(content_bytes)

        # Parse based on file format
        if ext == ".pdf":
            parsed_vulns = parse_vapt_pdf(temp_path, filename, db=db)
        elif ext == ".docx":
            parsed_vulns = parse_vapt_docx(temp_path, filename, db=db)
        elif ext == ".txt":
            parsed_vulns = parse_vapt_text(temp_path, filename, db=db)
        else:
            parsed_vulns = parse_vapt_image(temp_path, filename, db=db)

        user_id = current_user.id if current_user else 1
        db_report = report_service.create_report(db, filename, user_id=user_id)
        report_service.update_report(db, db_report.id, "Completed")

        saved_findings = []
        for v in parsed_vulns:
            v_obj = vulnerability_service.create_vulnerability(db, v)
            impl_steps = []
            verif_steps = []
            try:
                if v_obj.implementation_steps:
                    impl_steps = json.loads(v_obj.implementation_steps) if isinstance(v_obj.implementation_steps, str) else v_obj.implementation_steps
            except Exception:
                impl_steps = [v_obj.implementation_steps] if v_obj.implementation_steps else []
            try:
                if v_obj.verification_steps:
                    verif_steps = json.loads(v_obj.verification_steps) if isinstance(v_obj.verification_steps, str) else v_obj.verification_steps
            except Exception:
                verif_steps = [v_obj.verification_steps] if v_obj.verification_steps else []

            saved_findings.append({
                "id": v_obj.id,
                "vulnerability": v_obj.vulnerability_name,
                "cwe_id": v_obj.cwe_id,
                "cve_id": getattr(v_obj, "cve_id", None),
                "severity": v_obj.severity,
                "language": getattr(v_obj, "language", "Unknown") or "Unknown",
                "framework": getattr(v_obj, "framework", "Unknown") or "Unknown",
                "file": v_obj.file_name or "N/A",
                "line": v_obj.line_number or 1,
                "description": v_obj.description or "N/A",
                "why_vulnerable": getattr(v_obj, "why_vulnerable", "N/A"),
                "knowledge_base_remediation": getattr(v_obj, "remediation", "N/A"),
                "ai_remediation": getattr(v_obj, "ai_remediation", "N/A"),
                "secure_code": getattr(v_obj, "secure_code", "N/A"),
                "implementation_steps": impl_steps,
                "verification_steps": verif_steps
            })

        db_report.vulnerabilities_count = len(saved_findings)
        db.commit()

        return {
            "message": "Report uploaded and parsed with AI remediations successfully.",
            "report_id": db_report.id,
            "filename": filename,
            "status": "Completed",
            "vulnerabilities_count": len(saved_findings),
            "findings": saved_findings
        }

    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass


@router.post("/analyze/source-code")
async def analyze_source_code(
    file: Optional[UploadFile] = File(None),
    code_content: Optional[str] = Form(None),
    filename: Optional[str] = Form(None),
    language: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """
    Flow 2: Source Code Upload & Analysis
    Accepts single source code file (.py, .java, .cpp, .c, .js, .ts, .php, .cs, .go, .rb),
    or project ZIP archive, or pasted code string.
    Automatically detects language, framework, database, performs SAST, maps to KB,
    and returns language-specific AI remediations and secure replacement code.
    """
    user_id = current_user.id if current_user else 1

    # Case A: Direct pasted code content
    if code_content and code_content.strip():
        target_name = filename or "sample_code.txt"
        analysis, findings = source_code_service.process_single_file_upload(
            db=db,
            content=code_content,
            filename=target_name,
            user_id=user_id,
            language=language
        )
    # Case B: File upload
    elif file:
        file_name = file.filename or "uploaded_code"
        ext = os.path.splitext(file_name.lower())[1]

        if ext not in SOURCE_CODE_EXTENSIONS and ext != "":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported file extension '{ext}'. Supported extensions: .py, .java, .cpp, .c, .js, .ts, .php, .cs, .go, .rb, or .zip"
            )

        content_bytes = await file.read()

        if ext == ".zip":
            temp_zip = os.path.join(tempfile.gettempdir(), f"upload_{uuid.uuid4().hex}.zip")
            try:
                with open(temp_zip, "wb") as f:
                    f.write(content_bytes)
                analysis, findings = source_code_service.process_zip_upload(
                    db=db,
                    zip_path=temp_zip,
                    filename=file_name,
                    user_id=user_id
                )
            finally:
                if os.path.exists(temp_zip):
                    try:
                        os.remove(temp_zip)
                    except Exception:
                        pass
        else:
            code_text = content_bytes.decode("utf-8", errors="replace")
            analysis, findings = source_code_service.process_single_file_upload(
                db=db,
                content=code_text,
                filename=file_name,
                user_id=user_id,
                language=language
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either an uploaded source file or code_content string must be provided."
        )

    # Format structured findings
    formatted_findings = []
    for f in findings:
        impl_steps = []
        verif_steps = []
        try:
            if f.implementation_steps:
                impl_steps = json.loads(f.implementation_steps) if isinstance(f.implementation_steps, str) else f.implementation_steps
        except Exception:
            impl_steps = [f.implementation_steps] if f.implementation_steps else []
        try:
            if f.verification_steps:
                verif_steps = json.loads(f.verification_steps) if isinstance(f.verification_steps, str) else f.verification_steps
        except Exception:
            verif_steps = [f.verification_steps] if f.verification_steps else []

        formatted_findings.append({
            "id": f.id,
            "vulnerability": f.vulnerability_name,
            "cwe_id": f.cwe_id,
            "severity": f.severity,
            "language": f.language.capitalize() if f.language else "Unknown",
            "framework": f.framework or "Unknown",
            "file": f.file_name,
            "line": f.line_number,
            "description": f.description or "N/A",
            "why_vulnerable": f.why_vulnerable or "N/A",
            "knowledge_base_remediation": f.remediation or f.recommendation or "N/A",
            "ai_remediation": f.ai_remediation or "N/A",
            "vulnerable_code": f.matched_code or f.code_snippet or "N/A",
            "secure_code": f.secure_code or f.suggested_fix or "N/A",
            "implementation_steps": impl_steps,
            "verification_steps": verif_steps
        })

    return {
        "message": "Source code vulnerability analysis and remediation completed successfully.",
        "analysis_id": analysis.id,
        "project_name": analysis.project_name,
        "filename": analysis.filename,
        "files_scanned": analysis.files_scanned,
        "lines_scanned": analysis.lines_scanned,
        "vulnerabilities_found": analysis.vulnerabilities_count,
        "severity_summary": {
            "critical": analysis.critical_count,
            "high": analysis.high_count,
            "medium": analysis.medium_count,
            "low": analysis.low_count
        },
        "findings": formatted_findings
    }


@router.post("/analyze/combined")
async def analyze_combined(
    report_file: UploadFile = File(...),
    source_file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """
    Flow 3: VAPT Report + Source Code Combined Correlation
    Correlates findings in the uploaded penetration test report with ground-truth
    source code to verify whether vulnerabilities exist, locate exact code lines,
    and generate high-confidence language-specific remediations with verified replacement code.
    """
    rep_filename = report_file.filename or "report.pdf"
    src_filename = source_file.filename or "source.zip"

    rep_temp = os.path.join(tempfile.gettempdir(), f"comb_rep_{uuid.uuid4().hex}_{rep_filename}")
    src_temp = os.path.join(tempfile.gettempdir(), f"comb_src_{uuid.uuid4().hex}_{src_filename}")

    try:
        rep_bytes = await report_file.read()
        src_bytes = await source_file.read()

        with open(rep_temp, "wb") as f:
            f.write(rep_bytes)
        with open(src_temp, "wb") as f:
            f.write(src_bytes)

        result = correlate_report_and_code(
            report_path=rep_temp,
            report_filename=rep_filename,
            source_path_or_content=src_temp,
            source_filename=src_filename,
            db=db
        )

        return result

    finally:
        for p in (rep_temp, src_temp):
            if os.path.exists(p):
                try:
                    os.remove(p)
                except Exception:
                    pass


@router.post("/remediation/generate")
def generate_custom_remediation(payload: RemediationGenerateRequest):
    """
    Centralized AI Remediation Generation Endpoint
    Accepts structured vulnerability context and returns language-specific,
    framework-aware remediation, root cause explanation, and secure replacement code.
    """
    result = generate_remediation(
        vulnerability=payload.vulnerability,
        cwe_id=payload.cwe_id,
        severity=payload.severity,
        language=payload.language,
        framework=payload.framework,
        database_or_lib=payload.database_or_lib,
        file_name=payload.file_name,
        line_number=payload.line_number,
        vulnerable_code=payload.vulnerable_code,
        description=payload.description,
        kb_remediation=payload.kb_remediation
    )
    return result


@router.get("/vulnerabilities", response_model=List[VulnerabilityResponse])
def list_api_vulnerabilities(
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Returns all vulnerabilities with attached AI remediation."""
    if current_user:
        user_reports = db.query(Report).filter(Report.user_id == current_user.id).all()
        rep_names = [r.filename for r in user_reports]
        if not rep_names:
            return []
        vulns = db.query(Vulnerability).filter(Vulnerability.report_name.in_(rep_names)).all()
    else:
        vulns = db.query(Vulnerability).all()

    for v in vulns:
        vulnerability_service.attach_kb_details(db, v)
    return vulns


@router.get("/vulnerabilities/{vulnerability_id}", response_model=VulnerabilityResponse)
def get_api_vulnerability(
    vulnerability_id: int,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Returns detailed finding with AI remediation."""
    v = vulnerability_service.get_vulnerability(db, vulnerability_id)
    if not v:
        raise HTTPException(status_code=404, detail="Vulnerability not found.")
    return v
