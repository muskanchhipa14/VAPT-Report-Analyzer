import os
import uuid
import json
import tempfile
from sqlalchemy.orm import Session
from typing import List, Optional, Tuple

from app.models.source_code import SourceCodeAnalysis, SourceCodeFinding
from app.source_scanner.scanner import scan_directory, scan_single_file_content
from app.source_scanner.utils import safe_extract_zip, cleanup_directory
from app.services.ai_remediation_service import generate_remediation


def _populate_finding_with_ai(finding_obj, scan_finding):
    """Fills finding with language-specific AI remediation and secure code."""
    res = generate_remediation(
        vulnerability=scan_finding.vulnerability_name,
        cwe_id=scan_finding.cwe_id,
        severity=scan_finding.severity,
        language=scan_finding.language,
        framework=scan_finding.framework,
        database_or_lib=scan_finding.database_or_lib,
        file_name=scan_finding.file_name,
        line_number=scan_finding.line_number,
        vulnerable_code=scan_finding.matched_code or scan_finding.code_snippet,
        description=scan_finding.description,
        kb_remediation=scan_finding.remediation or scan_finding.recommendation
    )
    finding_obj.framework = res.get("framework", scan_finding.framework or "Unknown")
    finding_obj.why_vulnerable = res.get("why_vulnerable")
    finding_obj.ai_remediation = res.get("ai_remediation")
    finding_obj.secure_code = res.get("secure_code")
    finding_obj.implementation_steps = json.dumps(res.get("implementation_steps", []))
    finding_obj.verification_steps = json.dumps(res.get("verification_steps", []))


def process_zip_upload(
    db: Session,
    zip_path: str,
    filename: str,
    user_id: int
) -> Tuple[SourceCodeAnalysis, List[SourceCodeFinding]]:
    """
    Safely extracts uploaded ZIP archive, scans extracted source files,
    persists findings enriched with AI remediation into database, and cleans up temporary files.
    """
    temp_dir = os.path.join(tempfile.gettempdir(), f"sast_scan_{uuid.uuid4().hex}")
    
    try:
        safe_extract_zip(zip_path, temp_dir)
        summary = scan_directory(temp_dir, db=db)

        project_name = os.path.splitext(filename)[0] or "Source Project"

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
                owasp_category=finding.owasp_category,
                framework=finding.framework
            )
            _populate_finding_with_ai(db_finding, finding)
            db.add(db_finding)
            saved_findings.append(db_finding)

        db.commit()
        for f in saved_findings:
            db.refresh(f)

        return analysis, saved_findings

    finally:
        cleanup_directory(temp_dir)


def process_single_file_upload(
    db: Session,
    content: str,
    filename: str,
    user_id: int,
    language: Optional[str] = None
) -> Tuple[SourceCodeAnalysis, List[SourceCodeFinding]]:
    """
    Scans a single uploaded source file, creates analysis record, and attaches AI remediations.
    """
    file_result = scan_single_file_content(content=content, filename=filename, language=language, db=db)
    findings = file_result.findings if file_result else []

    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        sev = f.severity.capitalize() if f.severity else "Medium"
        if sev in sev_counts:
            sev_counts[sev] += 1
        else:
            sev_counts["Medium"] += 1

    project_name = os.path.splitext(filename)[0] or "Single File Scan"

    analysis = SourceCodeAnalysis(
        project_name=project_name,
        filename=filename,
        status="Completed",
        files_scanned=1,
        lines_scanned=file_result.line_count if file_result else len(content.splitlines()),
        vulnerabilities_count=len(findings),
        critical_count=sev_counts["Critical"],
        high_count=sev_counts["High"],
        medium_count=sev_counts["Medium"],
        low_count=sev_counts["Low"],
        user_id=user_id
    )

    db.add(analysis)
    db.commit()
    db.refresh(analysis)

    saved_findings = []
    for finding in findings:
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
            owasp_category=finding.owasp_category,
            framework=finding.framework
        )
        _populate_finding_with_ai(db_finding, finding)
        db.add(db_finding)
        saved_findings.append(db_finding)

    db.commit()
    for f in saved_findings:
        db.refresh(f)

    return analysis, saved_findings


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
