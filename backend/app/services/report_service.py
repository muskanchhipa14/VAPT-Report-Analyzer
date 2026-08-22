from sqlalchemy.orm import Session
from app.models.report import Report
from fastapi import UploadFile
import os
import shutil

from app.services.pdf_parser import parse_pdf_report
from app.services.vulnerability_service import attach_kb_details

def create_report(db: Session, filename: str):
    report = Report(filename=filename)
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


def get_reports(db: Session):
    return db.query(Report).all()


def get_report(db: Session, report_id: int):
    return db.query(Report).filter(Report.id == report_id).first()


def update_report(db: Session, report_id: int, status: str):
    report = get_report(db, report_id)

    if report:
        report.status = status
        db.commit()
        db.refresh(report)

    return report


def delete_report(db: Session, report_id: int):
    report = get_report(db, report_id)

    if report:
        db.delete(report)
        db.commit()

    return report

def upload_report(db: Session, file: UploadFile):

    upload_dir = "uploads"

    os.makedirs(upload_dir, exist_ok=True)

    file_path = os.path.join(upload_dir, file.filename)

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # 1. Create Report row
    report = Report(
        filename=file.filename,
        status="Processing"
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    # 2. Extract PDF text & detect vulnerabilities
    detected_vulns = []
    try:
        detected_vulns = parse_pdf_report(db, file_path, report.filename)
    except Exception as e:
        print(f"Error parsing PDF: {e}")
        report.status = "Failed"
        db.commit()
        return {
            "message": f"Failed to analyze report: {str(e)}",
            "report_id": report.id,
            "filename": report.filename,
            "status": report.status,
            "vulnerabilities_count": 0,
            "detected_vulnerabilities": []
        }

    # 3. Attach knowledge base details (description, remediation) to the objects
    for v in detected_vulns:
        attach_kb_details(db, v)

    # 4. Update Report with final counts and status
    report.vulnerabilities_count = len(detected_vulns)
    report.status = "Analyzed"
    db.commit()
    db.refresh(report)

    return {
        "message": "Report uploaded and analyzed successfully.",
        "report_id": report.id,
        "filename": report.filename,
        "status": report.status,
        "vulnerabilities_count": report.vulnerabilities_count,
        "detected_vulnerabilities": [
            {
                "id": v.id,
                "report_name": v.report_name,
                "vulnerability_name": v.vulnerability_name,
                "severity": v.severity,
                "cwe_id": v.cwe_id,
                "file_name": v.file_name,
                "line_number": v.line_number,
                "status": v.status,
                "description": getattr(v, "description", "N/A"),
                "remediation": getattr(v, "remediation", "N/A")
            } for v in detected_vulns
        ]
    }