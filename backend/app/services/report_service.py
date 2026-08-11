from sqlalchemy.orm import Session
from app.models.report import Report
from fastapi import UploadFile
import os
import shutil

from app.services.pdf_parser import extract_text_from_pdf

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

async def upload_report(db: Session, file: UploadFile):

    upload_dir = "uploads"

    os.makedirs(upload_dir, exist_ok=True)

    file_path = os.path.join(upload_dir, file.filename)

    # Save uploaded PDF
    contents = await file.read()

    if not contents:
        raise ValueError("Uploaded PDF is empty.")

    with open(file_path, "wb") as buffer:
        buffer.write(contents)

    # Extract text from PDF
    try:
        extracted_text = extract_text_from_pdf(file_path)
    except Exception as e:
        raise ValueError(
            f"Failed to extract text from PDF: {str(e)}"
        )

    # Check whether text was extracted
    if not extracted_text.strip():
        raise ValueError(
            "No readable text could be extracted from this PDF."
        )

    # Create report database record
    report = Report(
        filename=file.filename,
        status="Uploaded"
    )

    db.add(report)
    db.commit()
    db.refresh(report)

    return {
        "message": "Report uploaded and parsed successfully.",
        "report_id": report.id,
        "filename": report.filename,
        "status": report.status,
        "text_length": len(extracted_text),
        "extracted_text": extracted_text
    }