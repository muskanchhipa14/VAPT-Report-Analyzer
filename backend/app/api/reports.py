from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import FileResponse
import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

router = APIRouter(prefix="/reports", tags=["Reports"])

REPORT_DIR = "generated_reports"
os.makedirs(REPORT_DIR, exist_ok=True)

@router.get("/")
def get_reports():
    """
    Read: View uploaded reports and their processing status.
    """
    # Placeholder for database/storage report retrieval
    reports = [
        {"report_id": "rep_001", "filename": "sample_vapt.pdf", "status": "Processed", "vulnerabilities_count": 4}
    ]
    return {"status": "success", "reports": reports}

@router.post("/generate-pdf/{report_id}")
def generate_pdf_report(report_id: str):
    """
    Create / Update: Generate or regenerate a downloadable PDF analysis report using ReportLab.
    """
    file_path = os.path.join(REPORT_DIR, f"Analysis_Report_{report_id}.pdf")
    
    try:
        # Build PDF using ReportLab
        doc = SimpleDocTemplate(file_path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        # Title
        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Heading1'],
            fontSize=20,
            spaceAfter=15
        )
        story.append(Paragraph(f"VAPT Security Analysis Report - {report_id}", title_style))
        story.append(Spacer(1, 10))

        # Summary section
        story.append(Paragraph("<b>Executive Summary:</b> This document outlines the security vulnerabilities detected during the automated VAPT scan, along with corresponding remediation guidelines.", styles['Normal']))
        story.append(Spacer(1, 15))

        # Vulnerability findings table placeholder text
        story.append(Paragraph("<b>Key Findings:</b>", styles['Heading2']))
        story.append(Paragraph("1. CWE-79: Cross-Site Scripting (XSS) - High Severity", styles['Normal']))
        story.append(Paragraph("2. CWE-89: SQL Injection - Critical Severity", styles['Normal']))
        
        doc.build(story)

        return FileResponse(file_path, media_type='application/pdf', filename=f"Analysis_Report_{report_id}.pdf")
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating PDF report: {str(e)}")

@router.delete("/{report_id}")
def delete_report(report_id: str):
    """
    Delete: Remove an uploaded report and its analysis logs.
    """
    file_path = os.path.join(REPORT_DIR, f"Analysis_Report_{report_id}.pdf")
    if os.path.exists(file_path):
        os.remove(file_path)
    return {"status": "success", "message": f"Report {report_id} deleted successfully."}