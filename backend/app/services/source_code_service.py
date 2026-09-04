import os
import uuid
import tempfile
from sqlalchemy.orm import Session
from typing import List, Optional, Tuple

from app.models.source_code import SourceCodeAnalysis, SourceCodeFinding
from app.source_scanner.scanner import scan_directory
from app.source_scanner.utils import safe_extract_zip, cleanup_directory


def process_zip_upload(
    db: Session,
    zip_path: str,
    filename: str,
    user_id: int
) -> Tuple[SourceCodeAnalysis, List[SourceCodeFinding]]:
    """
    Safely extracts uploaded ZIP archive, scans extracted source files,
    persists findings into database, and cleans up temporary files.
    """
    # Create unique temp extract directory
    temp_dir = os.path.join(tempfile.gettempdir(), f"sast_scan_{uuid.uuid4().hex}")
    
    try:
        # Safe extraction (Zip Slip protection + size/count quotas)
        safe_extract_zip(zip_path, temp_dir)

        # Run multi-language static scanning engine
        summary = scan_directory(temp_dir, db=db)

        project_name = os.path.splitext(filename)[0]
        if not project_name:
            project_name = "Source Project"

        analysis = SourceCodeAnalysis(
            project_name=project_name,
            filename=filename,
            status="Completed",
            files_scanned=summary.files_scanned,
            lines_scanned=summary.lines_scanned,
            vulnerabilities_count=summary.vulnerabilities_found,
            critical_count=summary.severity_counts.get("Critical", 0),
            high_count=summary.severity_counts.get("High", 0),
            medium_count=summary.severity_counts.get("Medium", 0),
            low_count=summary.severity_counts.get("Low", 0),
            user_id=user_id
        )

        db.add(analysis)
        db.commit()
        db.refresh(analysis)

        saved_findings = []
        for finding in summary.findings:
            db_finding = SourceCodeFinding(
                analysis_id=analysis.id,
                file_name=finding.file_name,
                line_number=finding.line_number,
                language=finding.language,
                vulnerability_name=finding.vulnerability_name,
                cwe_id=finding.cwe_id,
                severity=finding.severity,
                confidence=finding.confidence,
                matched_code=finding.matched_code,
                code_snippet=finding.code_snippet,
                suggested_fix=finding.suggested_fix,
                description=finding.description,
                remediation=finding.remediation,
                recommendation=finding.recommendation,
                owasp_category=finding.owasp_category
            )
            db.add(db_finding)
            saved_findings.append(db_finding)

        db.commit()
        for f in saved_findings:
            db.refresh(f)

        return analysis, saved_findings

    finally:
        # Guarantee cleanup of unzipped files
        cleanup_directory(temp_dir)


def get_analyses_by_user(db: Session, user_id: int) -> List[SourceCodeAnalysis]:
    return (
        db.query(SourceCodeAnalysis)
        .filter(SourceCodeAnalysis.user_id == user_id)
        .order_by(SourceCodeAnalysis.created_at.desc())
        .all()
    )


def get_analysis(db: Session, analysis_id: int) -> Optional[SourceCodeAnalysis]:
    return (
        db.query(SourceCodeAnalysis)
        .filter(SourceCodeAnalysis.id == analysis_id)
        .first()
    )


def delete_analysis(db: Session, analysis_id: int) -> Optional[SourceCodeAnalysis]:
    analysis = get_analysis(db, analysis_id)
    if analysis:
        db.delete(analysis)
        db.commit()
    return analysis
