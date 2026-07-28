from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.report import (
    ReportCreate,
    ReportUpdate,
    ReportResponse
)
from app.services import report_service
from app.services.audit_helper import log_event

router = APIRouter(
    prefix="/reports",
    tags=["Reports"]
)


@router.post("/", response_model=ReportResponse)
def create_report(
    report: ReportCreate,
    db: Session = Depends(get_db)
):
    new_report = report_service.create_report(db, report.filename)

    log_event(
        db,
        "System",
        "Create Report",
        "Report Management",
        "Success"
    )

    return new_report


@router.get("/", response_model=list[ReportResponse])
def read_reports(
    db: Session = Depends(get_db)
):
    reports = report_service.get_reports(db)

    log_event(
        db,
        "System",
        "View All Reports",
        "Report Management",
        "Success"
    )

    return reports


@router.get("/{report_id}", response_model=ReportResponse)
def read_report(
    report_id: int,
    db: Session = Depends(get_db)
):
    report = report_service.get_report(db, report_id)

    if not report:
        raise HTTPException(
            status_code=404,
            detail="Report not found"
        )

    log_event(
        db,
        "System",
        "View Report",
        "Report Management",
        "Success"
    )

    return report


@router.put("/{report_id}", response_model=ReportResponse)
def update_report(
    report_id: int,
    report: ReportUpdate,
    db: Session = Depends(get_db)
):
    updated = report_service.update_report(
        db,
        report_id,
        report.status
    )

    if not updated:
        raise HTTPException(
            status_code=404,
            detail="Report not found"
        )

    log_event(
        db,
        "System",
        "Update Report",
        "Report Management",
        "Success"
    )

    return updated


@router.delete("/{report_id}")
def delete_report(
    report_id: int,
    db: Session = Depends(get_db)
):
    deleted = report_service.delete_report(db, report_id)

    if not deleted:
        raise HTTPException(
            status_code=404,
            detail="Report not found"
        )

    log_event(
        db,
        "System",
        "Delete Report",
        "Report Management",
        "Success"
    )

    return {
        "status": "success",
        "message": f"Report {report_id} deleted successfully."
    }

@router.post("/upload")
def upload_report(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    if not file.filename.endswith(".pdf"):
        raise HTTPException(
            status_code=400,
            detail="Only PDF files are allowed."
        )

    return report_service.upload_report(db, file)