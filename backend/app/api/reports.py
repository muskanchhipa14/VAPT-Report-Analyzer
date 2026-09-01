import os
from fastapi import APIRouter, Depends, HTTPException, File, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.schemas.report import (
    ReportCreate,
    ReportUpdate,
    ReportResponse
)
from app.services import report_service, vulnerability_service
from app.services.pdf_parser import parse_vapt_pdf, parse_vapt_docx
from app.services.report_generator import generate_vapt_pdf_report
from app.services.audit_helper import log_event
from app.core.security import get_current_user

router = APIRouter(
    prefix="/reports",
    tags=["Reports"]
)

# Directory to store uploaded PDFs
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


@router.post("/", response_model=ReportResponse)
def create_report(
    report: ReportCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    new_report = report_service.create_report(db, report.filename, user_id=current_user.id)

    log_event(
        db,
        current_user.name,
        f"Create Report Record: {report.filename}",
        "Report Management",
        "Success"
    )

    return new_report


@router.post("/upload")
def upload_report(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    ext = os.path.splitext(file.filename.lower())[1]
    if ext not in [".pdf", ".docx"]:
        raise HTTPException(status_code=400, detail="Only PDF and DOCX files are supported.")

    filename = file.filename
    file_path = os.path.join(UPLOAD_DIR, filename)
    
    # Save the file
    try:
        with open(file_path, "wb") as f:
            f.write(file.file.read())
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save uploaded file: {str(e)}")

    # 1. Create Report in DB associated with the current logged-in user
    db_report = report_service.create_report(db, filename, user_id=current_user.id)
    report_service.update_report(db, db_report.id, "Parsing")
    
    try:
        if ext == ".pdf":
            parsed_vulns = parse_vapt_pdf(file_path, filename, db=db)
        else:
            parsed_vulns = parse_vapt_docx(file_path, filename, db=db)
        
        # 3. Save vulnerabilities to DB and attach KB details
        saved_vulns = []
        for vuln in parsed_vulns:
            v_obj = vulnerability_service.create_vulnerability(db, vuln)
            saved_vulns.append({
                "id": v_obj.id,
                "report_name": v_obj.report_name,
                "vulnerability_name": v_obj.vulnerability_name,
                "severity": v_obj.severity,
                "cwe_id": v_obj.cwe_id,
                "file_name": v_obj.file_name,
                "line_number": v_obj.line_number,
                "status": v_obj.status,
                "description": getattr(v_obj, "description", "N/A"),
                "remediation": getattr(v_obj, "remediation", "N/A")
            })
            
        # 4. Update Report record status and vulnerabilities count
        db_report.vulnerabilities_count = len(saved_vulns)
        db_report.status = "Completed"
        db.commit()
        db.refresh(db_report)
        
        log_event(
            db,
            current_user.name,
            f"Uploaded & Parsed Report: {filename}",
            "Report Management",
            "Success"
        )
        
        return {
            "message": "Report uploaded and parsed successfully",
            "report_id": db_report.id,
            "filename": db_report.filename,
            "status": "Completed",
            "vulnerabilities_count": len(saved_vulns),
            "vulnerabilities_found": len(saved_vulns),
            "detected_vulnerabilities": saved_vulns
        }
        
    except Exception as e:
        db_report.status = "Failed"
        db.commit()
        
        log_event(
            db,
            current_user.name,
            f"Failed to parse report: {filename}",
            "Report Management",
            "Failed"
        )
        
        raise HTTPException(
            status_code=500,
            detail=f"An error occurred while parsing the VAPT report: {str(e)}"
        )


@router.get("/", response_model=list[ReportResponse])
def read_reports(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    # Filter reports by user ID
    reports = report_service.get_reports_by_user(db, current_user.id)

    log_event(
        db,
        current_user.name,
        "Viewed User Reports",
        "Report Management",
        "Success"
    )

    return reports


@router.get("/{report_id}", response_model=ReportResponse)
def read_report(
    report_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    report = report_service.get_report(db, report_id)

    if not report:
        raise HTTPException(
            status_code=404,
            detail="Report not found"
        )

    if report.user_id != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="Not authorized to access this report"
        )

    log_event(
        db,
        current_user.name,
        f"Viewed Report ID: {report_id}",
        "Report Management",
        "Success"
    )

    return report


@router.get("/{report_id}/download")
def download_pdf_report(
    report_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    # Fetch report
    report = report_service.get_report(db, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
        
    if report.user_id != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="Not authorized to access this report"
        )
        
    # Fetch vulnerabilities belonging to this report
    from app.models.vulnerability import Vulnerability
    vulnerabilities = db.query(Vulnerability).filter(Vulnerability.report_name == report.filename).all()
    
    # Generate ReportLab PDF on-the-fly
    try:
        report_meta = {
            "filename": report.filename,
            "status": report.status,
            "vulnerabilities_count": report.vulnerabilities_count
        }
        pdf_buffer = generate_vapt_pdf_report(report_meta, vulnerabilities, db)
        
        log_event(
            db,
            current_user.name,
            f"Downloaded PDF Report ID: {report_id}",
            "Report Management",
            "Success"
        )
        
        # Stream PDF back to frontend
        return StreamingResponse(
            pdf_buffer,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=VAPT_Analysis_Report_{report_id}.pdf"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF report: {str(e)}")


@router.put("/{report_id}", response_model=ReportResponse)
def update_report(
    report_id: int,
    report: ReportUpdate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    db_report = report_service.get_report(db, report_id)
    if not db_report:
        raise HTTPException(status_code=404, detail="Report not found")
        
    if db_report.user_id != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="Not authorized to modify this report"
        )

    updated = report_service.update_report(
        db,
        report_id,
        report.status
    )

    log_event(
        db,
        current_user.name,
        f"Updated Status of Report ID: {report_id}",
        "Report Management",
        "Success"
    )

    return updated


@router.delete("/{report_id}")
def delete_report(
    report_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    report = report_service.get_report(db, report_id)
    if not report:
        raise HTTPException(
            status_code=404,
            detail="Report not found"
        )

    if report.user_id != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="Not authorized to delete this report"
        )

    # Delete all vulnerabilities associated with this report
    from app.models.vulnerability import Vulnerability
    db.query(Vulnerability).filter(Vulnerability.report_name == report.filename).delete(synchronize_session=False)
    
    # Delete report
    deleted = report_service.delete_report(db, report_id)

    log_event(
        db,
        current_user.name,
        f"Deleted Report ID: {report_id}",
        "Report Management",
        "Success"
    )

    return {
        "status": "success",
        "message": f"Report {report_id} and its vulnerabilities deleted successfully."
    }