import os
import shutil
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.config import settings
from app.models.report import Report
from app.models.vulnerability import Vulnerability
from app.schemas.evaluation import (
    ReportEvaluationResponse,
    EvaluationStatusResponse
)
from app.services.pdf_parser import parse_pdf_report, deduplicate_vulnerabilities
from app.services.vulnerability_service import attach_kb_details
from app.services.gemini_evaluator import evaluate_report_vulnerabilities
from app.services.evaluation_metrics import calculate_metrics
from app.services.audit_helper import log_event

router = APIRouter(
    tags=["Evaluation"]
)


@router.get("/evaluation/status", response_model=EvaluationStatusResponse)
def get_evaluation_status():
    """
    Checks if Google Gemini API is configured in backend environment
    without exposing the actual API key.
    """
    configured = settings.is_gemini_configured
    msg = (
        "Google Gemini API is ready for independent evaluation."
        if configured
        else "GEMINI_API_KEY is not set. Please configure GEMINI_API_KEY in .env."
    )
    return EvaluationStatusResponse(
        configured=configured,
        model=settings.GEMINI_MODEL,
        provider="Google GenAI SDK (google-genai)",
        message=msg
    )


@router.post("/evaluate-report", response_model=ReportEvaluationResponse)
@router.post("/reports/evaluate", response_model=ReportEvaluationResponse)
def evaluate_report_upload(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """
    1. Accepts uploaded VAPT PDF.
    2. Runs existing PDF text extraction & vulnerability detection.
    3. Deduplicates findings using stable (name, CWE, file, line) identity.
    4. Searches existing Knowledge Base for remediations.
    5. Submits each unique detection + KB remediation to Gemini for independent evaluation.
    6. Calculates precision, recall, f1, accuracy, and coverage metrics (excluding failed calls).
    7. Returns structured evaluation report.
    """
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(
            status_code=400,
            detail="Only PDF files are allowed for report evaluation."
        )

    upload_dir = settings.UPLOAD_DIR
    os.makedirs(upload_dir, exist_ok=True)
    file_path = os.path.join(upload_dir, file.filename)

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # 1. Create / Track Report
    report = Report(filename=file.filename, status="Evaluating")
    db.add(report)
    db.commit()
    db.refresh(report)

    # 2. Run existing PDF parsing & vulnerability detection
    try:
        detected_vulns = parse_pdf_report(db, file_path, report.filename)
    except Exception as e:
        report.status = "Evaluation Failed"
        db.commit()
        raise HTTPException(
            status_code=500,
            detail=f"Failed to parse PDF report: {str(e)}"
        )

    # 3. Deduplicate findings
    unique_vulns = deduplicate_vulnerabilities(detected_vulns)

    # 4. Attach existing Knowledge Base details & remediations
    for v in unique_vulns:
        attach_kb_details(db, v)

    report.vulnerabilities_count = len(unique_vulns)
    report.status = "Evaluated"
    db.commit()
    db.refresh(report)

    # 5. Evaluate with Gemini
    evaluations = evaluate_report_vulnerabilities(unique_vulns, report.filename)

    # 6. Compute Metrics
    metrics = calculate_metrics(evaluations, len(unique_vulns))

    log_event(
        db,
        "System",
        f"Evaluated Report '{report.filename}' with Gemini",
        "AI Evaluation",
        "Success"
    )

    return ReportEvaluationResponse(
        report_id=report.id,
        report_name=report.filename,
        total_vulnerabilities=len(unique_vulns),
        total_findings=len(unique_vulns),
        evaluation_type="LLM-based Evaluation (Gemini Reference Judge)",
        disclaimer=(
            "Accuracy is calculated only from successfully evaluated findings. "
            "API failures are excluded from accuracy calculations."
        ),
        metrics=metrics,
        evaluations=evaluations,
        status="success",
        message="VAPT report evaluated successfully with Google Gemini."
    )


@router.post("/reports/{report_id}/evaluate", response_model=ReportEvaluationResponse)
def evaluate_existing_report(
    report_id: int,
    db: Session = Depends(get_db)
):
    """
    Evaluates an already uploaded report by its ID using Gemini.
    Deduplicates findings to ensure unique vulnerability count.
    """
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail=f"Report #{report_id} not found.")

    # Retrieve vulnerabilities associated with this report
    raw_vulns = db.query(Vulnerability).filter(
        Vulnerability.report_name == report.filename
    ).all()

    # Deduplicate findings so multiple upload runs of the same file don't inflate finding count
    unique_vulns = deduplicate_vulnerabilities(raw_vulns)

    for v in unique_vulns:
        attach_kb_details(db, v)

    evaluations = evaluate_report_vulnerabilities(unique_vulns, report.filename)
    metrics = calculate_metrics(evaluations, len(unique_vulns))

    report.vulnerabilities_count = len(unique_vulns)
    report.status = "Evaluated"
    db.commit()

    log_event(
        db,
        "System",
        f"Evaluated Report #{report_id} ({report.filename}) with Gemini",
        "AI Evaluation",
        "Success"
    )

    return ReportEvaluationResponse(
        report_id=report.id,
        report_name=report.filename,
        total_vulnerabilities=len(unique_vulns),
        total_findings=len(unique_vulns),
        evaluation_type="LLM-based Evaluation (Gemini Reference Judge)",
        disclaimer=(
            "Accuracy is calculated only from successfully evaluated findings. "
            "API failures are excluded from accuracy calculations."
        ),
        metrics=metrics,
        evaluations=evaluations,
        status="success",
        message="VAPT report evaluated successfully with Google Gemini."
    )
