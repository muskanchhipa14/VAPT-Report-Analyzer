"""
Continuous Vulnerability Remediation API Router
Provides endpoints to create, monitor, cancel, and export continuous remediation jobs.
Guarded by C-DAC Role-Based Access Control (RBAC).
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status, Query, Response
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session
from typing import List, Optional

from app.core.database import get_db
from app.core.security import get_current_user, require_source_code_access
from app.models.user import User
from app.models.source_code import RemediationJob, RemediationAttempt
from app.schemas.remediation import RemediationJobCreate, RemediationJobResponse, RemediationAttemptResponse
from app.services.remediation_loop_service import RemediationLoopService


router = APIRouter(
    prefix="/api/remediation",
    tags=["Continuous Vulnerability Remediation Loop"]
)


@router.post("/jobs", response_model=RemediationJobResponse)
def create_remediation_job(
    req: RemediationJobCreate,
    background_tasks: BackgroundTasks,
    sync: bool = Query(False, description="Run synchronously for immediate verification/testing"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_source_code_access)
):
    """
    Creates and initiates a continuous vulnerability remediation job.
    Enforces C-DAC Role-Based Access Control clearance.
    """
    job = RemediationLoopService.create_job(
        db=db,
        user=current_user,
        finding_id=req.finding_id,
        vulnerability_id=req.vulnerability_id,
        analysis_id=req.analysis_id,
        code_snippet=req.code_snippet,
        file_path=req.file_path,
        line_number=req.line_number,
        language=req.language,
        framework=req.framework,
        cwe_id=req.cwe_id,
        vulnerability_name=req.vulnerability_name,
        severity=req.severity,
        max_attempts=req.max_attempts,
        timeout_seconds=req.timeout_seconds
    )

    if sync:
        # Run synchronously (ideal for testing)
        RemediationLoopService.run_remediation_loop(job.id)
        db.refresh(job)
    else:
        # Run asynchronously in background worker
        background_tasks.add_task(RemediationLoopService.run_remediation_loop, job.id)

    return job


@router.get("/jobs/{job_id}", response_model=RemediationJobResponse)
def get_remediation_job(
    job_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_source_code_access)
):
    """Retrieves current state, attempt metrics, and progress for a remediation job."""
    job = db.query(RemediationJob).filter(RemediationJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Remediation job not found.")

    # Authorization ownership check (Officers & Analysts can view all, users can view own)
    if current_user.role not in ("cdac_officer", "admin", "security_officer") and job.user_id and job.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Forbidden: You do not have permission to view this remediation job.")

    return job


@router.get("/jobs/{job_id}/attempts", response_model=List[RemediationAttemptResponse])
def get_job_attempts(
    job_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_source_code_access)
):
    """Retrieves chronological attempt history, including patch diffs and validation errors."""
    job = db.query(RemediationJob).filter(RemediationJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Remediation job not found.")

    if current_user.role not in ("cdac_officer", "admin", "security_officer") and job.user_id and job.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Forbidden: You do not have permission to view this remediation job.")

    attempts = db.query(RemediationAttempt).filter(RemediationAttempt.job_id == job_id).order_by(RemediationAttempt.attempt_number).all()
    return attempts


@router.get("/jobs/{job_id}/diff")
def get_verified_patch_diff(
    job_id: int,
    format: str = Query("json", description="'json' or 'text'"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_source_code_access)
):
    """Retrieves the unified git/diff of the verified patch."""
    job = db.query(RemediationJob).filter(RemediationJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Remediation job not found.")

    if current_user.role not in ("cdac_officer", "admin", "security_officer") and job.user_id and job.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Forbidden: You do not have permission to view this remediation job.")

    diff_content = job.final_patch_diff or ""
    if not diff_content and job.attempts:
        # Check latest attempt diff
        latest_att = job.attempts[-1]
        diff_content = latest_att.patch_diff or ""

    if format == "text":
        return PlainTextResponse(diff_content, media_type="text/plain")

    return {
        "job_id": job.id,
        "job_uuid": job.job_uuid,
        "state": job.state,
        "cwe_id": job.cwe_id,
        "file_path": job.file_path,
        "patch_diff": diff_content,
        "verified_fixed": job.state == "VERIFIED_FIXED"
    }


@router.post("/jobs/{job_id}/cancel", response_model=RemediationJobResponse)
def cancel_remediation_job(
    job_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_source_code_access)
):
    """Requests immediate cancellation of a running remediation job and reverts working files."""
    job = db.query(RemediationJob).filter(RemediationJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Remediation job not found.")

    if current_user.role not in ("cdac_officer", "admin", "security_officer") and job.user_id and job.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Forbidden: You do not have permission to cancel this remediation job.")

    cancelled_job = RemediationLoopService.cancel_job(db=db, job_id=job_id, user=current_user)
    return cancelled_job


@router.post("/jobs/{job_id}/export")
def export_verified_patch(
    job_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_source_code_access)
):
    """
    Exports and downloads the independently verified patch diff.
    Only available after remediation is verified fixed.
    """
    job = db.query(RemediationJob).filter(RemediationJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Remediation job not found.")

    if current_user.role not in ("cdac_officer", "admin", "security_officer") and job.user_id and job.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Forbidden: You do not have permission to export patches for this remediation job.")

    if job.state != "VERIFIED_FIXED":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot export unverified patch. Current job state: '{job.state}'."
        )

    patch_content, filename = RemediationLoopService.export_verified_patch(db=db, job_id=job_id, user=current_user)
    if not patch_content:
        raise HTTPException(status_code=404, detail="No verified patch diff available for export.")

    return Response(
        content=patch_content,
        media_type="text/x-diff",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
