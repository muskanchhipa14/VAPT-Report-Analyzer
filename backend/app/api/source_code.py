import os
import tempfile
import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.schemas.source_code import (
    SourceCodeAnalysisResponse,
    SourceCodeAnalysisDetailResponse,
    SourceCodeScanUploadResponse,
    SourceCodeFindingResponse
)
from app.services import source_code_service
from app.services.report_generator import generate_source_code_pdf_report
from app.services.audit_helper import log_event

router = APIRouter(
    prefix="/source-code",
    tags=["Source Code Scanner"]
)

# Maximum ZIP upload size: 50MB
MAX_UPLOAD_SIZE_BYTES = 50 * 1024 * 1024


@router.post("/analyze", response_model=SourceCodeScanUploadResponse)
async def analyze_source_code(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Accepts project ZIP archive, safely unpacks it, performs AST / structural
    vulnerability analysis, attaches remediation from Knowledge Base, and stores findings.
    """
    filename = file.filename or "project.zip"
    ext = os.path.splitext(filename.lower())[1]

    if ext != ".zip":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only ZIP archive files (.zip) are supported for source code scanning."
        )

    log_event(
        db,
        current_user.name,
        f"Started Source Code Upload: {filename}",
        "Source Code Scanner",
        "Started"
    )

    # Save to a temporary file
    temp_zip = os.path.join(tempfile.gettempdir(), f"upload_{uuid.uuid4().hex}.zip")
    total_size = 0

    try:
        with open(temp_zip, "wb") as f:
            while chunk := await file.read(1024 * 1024):  # 1MB chunks
                total_size += len(chunk)
                if total_size > MAX_UPLOAD_SIZE_BYTES:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"Uploaded ZIP file exceeds maximum size limit ({MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)}MB)."
                    )
                f.write(chunk)

        # Process and scan the archive
        analysis, findings = source_code_service.process_zip_upload(
            db=db,
            zip_path=temp_zip,
            filename=filename,
            user_id=current_user.id
        )

        log_event(
            db,
            current_user.name,
            f"Completed Source Code Analysis: {filename} ({len(findings)} findings)",
            "Source Code Scanner",
            "Success"
        )

        severity_summary = {
            "critical": analysis.critical_count,
            "high": analysis.high_count,
            "medium": analysis.medium_count,
            "low": analysis.low_count,
        }

        finding_responses = [SourceCodeFindingResponse.model_validate(f) for f in findings]

        return SourceCodeScanUploadResponse(
            message="Source code analysis completed successfully.",
            analysis_id=analysis.id,
            project_name=analysis.project_name,
            filename=analysis.filename,
            files_scanned=analysis.files_scanned,
            lines_scanned=analysis.lines_scanned,
            vulnerabilities_found=analysis.vulnerabilities_count,
            severity_summary=severity_summary,
            findings=finding_responses
        )

    except HTTPException:
        raise
    except Exception as e:
        log_event(
            db,
            current_user.name,
            f"Failed Source Code Analysis: {filename} - {str(e)}",
            "Source Code Scanner",
            "Failed"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while scanning source code: {str(e)}"
        )
    finally:
        if os.path.exists(temp_zip):
            try:
                os.remove(temp_zip)
            except Exception:
                pass


@router.get("/analyses", response_model=List[SourceCodeAnalysisResponse])
def list_analyses(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Lists all source code analyses conducted by current user."""
    analyses = source_code_service.get_analyses_by_user(db, current_user.id)
    return analyses


@router.get("/analyses/{analysis_id}", response_model=SourceCodeAnalysisDetailResponse)
def get_analysis_detail(
    analysis_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieves full details and vulnerability findings for a specific scan."""
    analysis = source_code_service.get_analysis(db, analysis_id)

    if not analysis:
        raise HTTPException(status_code=404, detail="Source code analysis record not found.")

    if analysis.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to access this analysis.")

    return analysis


@router.delete("/analyses/{analysis_id}")
def delete_analysis(
    analysis_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Deletes an analysis record and all associated findings."""
    analysis = source_code_service.get_analysis(db, analysis_id)

    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis record not found.")

    if analysis.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this analysis.")

    source_code_service.delete_analysis(db, analysis_id)

    log_event(
        db,
        current_user.name,
        f"Deleted Source Code Analysis ID: {analysis_id}",
        "Source Code Scanner",
        "Success"
    )

    return {
        "status": "success",
        "message": f"Analysis {analysis_id} and associated findings deleted successfully."
    }


@router.get("/analyses/{analysis_id}/download")
def download_analysis_report(
    analysis_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Generates and streams a PDF report for the given source code analysis."""
    analysis = source_code_service.get_analysis(db, analysis_id)

    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis record not found.")

    if analysis.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to download this report.")

    analysis_meta = {
        "project_name": analysis.project_name,
        "filename": analysis.filename,
        "status": analysis.status,
        "files_scanned": analysis.files_scanned,
        "lines_scanned": analysis.lines_scanned,
        "vulnerabilities_count": analysis.vulnerabilities_count,
    }

    try:
        pdf_buffer = generate_source_code_pdf_report(analysis_meta, analysis.findings, db)

        log_event(
            db,
            current_user.name,
            f"Downloaded SAST PDF Report ID: {analysis_id}",
            "Source Code Scanner",
            "Success"
        )

        filename = f"SAST_Security_Report_{analysis.project_name.replace(' ', '_')}.pdf"
        return StreamingResponse(
            pdf_buffer,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate source code security PDF report: {str(e)}"
        )
