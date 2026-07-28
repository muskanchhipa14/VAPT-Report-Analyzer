from sqlalchemy.orm import Session
from app.models.report import Report
from fastapi import UploadFile
import os
import shutil

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

    report = Report(
        filename=file.filename,
        status="Uploaded"
    )

    db.add(report)
    db.commit()
    db.refresh(report)

    return {
        "message": "Report uploaded successfully.",
        "report_id": report.id,
        "filename": report.filename,
        "status": report.status
    }