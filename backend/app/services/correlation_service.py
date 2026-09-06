"""
VAPT Report + Source Code Correlation Engine (Flow 3)
Correlates findings from penetration test reports with actual uploaded source code
to confirm vulnerabilities, eliminate false positives, and synthesize ground-truth remediations.
"""

import os
import re
import json
import tempfile
import uuid
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.services.pdf_parser import parse_vapt_pdf, parse_vapt_docx, parse_vapt_image, parse_vapt_text
from app.source_scanner.scanner import scan_directory, scan_single_file_content
from app.source_scanner.utils import safe_extract_zip, cleanup_directory
from app.services.ai_remediation_service import generate_remediation
from app.models.knowledge_base import KnowledgeBaseItem


def correlate_report_and_code(
    report_path: str,
    report_filename: str,
    source_path_or_content: str,
    source_filename: str,
    db: Session,
    is_source_content: bool = False
) -> Dict[str, Any]:
    """
    Correlates a VAPT report with uploaded source code file or project zip archive.
    Cross-references report claims against ground-truth static syntax analysis.
    """
    # 1. Parse Report
    report_ext = os.path.splitext(report_filename.lower())[1]
    report_vulns = []
    if report_ext == ".pdf":
        report_vulns = parse_vapt_pdf(report_path, report_filename, db=db)
    elif report_ext == ".docx":
        report_vulns = parse_vapt_docx(report_path, report_filename, db=db)
    elif report_ext in (".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tiff"):
        report_vulns = parse_vapt_image(report_path, report_filename, db=db)
    else:
        # Default to text parsing (.txt or unknown report format)
        report_vulns = parse_vapt_text(report_path, report_filename, db=db)

    # 2. Analyze Source Code
    source_findings = []
    source_files_map: Dict[str, str] = {}  # relative_name -> content

    source_ext = os.path.splitext(source_filename.lower())[1]
    temp_zip_dir = None

    try:
        if source_ext == ".zip" and not is_source_content:
            temp_zip_dir = os.path.join(tempfile.gettempdir(), f"correlate_zip_{uuid.uuid4().hex}")
            safe_extract_zip(source_path_or_content, temp_zip_dir)
            summary = scan_directory(temp_zip_dir, db=db)
            source_findings = summary.findings
            # Read files for content lookup
            for root, _, files in os.walk(temp_zip_dir):
                for f in files:
                    full = os.path.join(root, f)
                    rel = os.path.relpath(full, temp_zip_dir).replace("\\", "/")
                    try:
                        with open(full, "r", encoding="utf-8", errors="ignore") as fh:
                            source_files_map[rel] = fh.read()
                    except Exception:
                        pass
        else:
            # Single file analysis
            code_text = source_path_or_content
            if not is_source_content and os.path.exists(source_path_or_content):
                with open(source_path_or_content, "r", encoding="utf-8", errors="ignore") as fh:
                    code_text = fh.read()

            source_files_map[source_filename] = code_text
            file_res = scan_single_file_content(code_text, filename=source_filename, db=db)
            source_findings = file_res.findings if file_res else []

        # 3. Correlation Logic
        correlated_results: List[Dict[str, Any]] = []
        matched_sast_keys = set()

        for r_vuln in report_vulns:
            r_file = (r_vuln.file_name or "").replace("\\", "/").strip()
            r_cwe = (r_vuln.cwe_id or "").strip().upper()
            r_base = os.path.basename(r_file).lower()

            # Attempt to locate source file
            matched_source_file = None
            matched_source_content = None

            for s_name, s_content in source_files_map.items():
                s_base = os.path.basename(s_name).lower()
                if s_base == r_base or r_file.lower() in s_name.lower() or s_name.lower() in r_file.lower():
                    matched_source_file = s_name
                    matched_source_content = s_content
                    break

            # Check if SAST detected the same CWE in that file
            sast_match = None
            for s_find in source_findings:
                s_find_base = os.path.basename(s_find.file_name).lower()
                if s_find.cwe_id.upper() == r_cwe:
                    if not matched_source_file or s_find_base == os.path.basename(matched_source_file).lower():
                        sast_match = s_find
                        matched_sast_keys.add((s_find.file_name, s_find.line_number, s_find.cwe_id))
                        break

            # Determine correlation status & confidence
            if sast_match:
                status = "CONFIRMED"
                confidence = "High (Verified against Source Code)"
                target_file = sast_match.file_name
                target_line = sast_match.line_number
                actual_code = sast_match.matched_code or sast_match.code_snippet
                lang = sast_match.language
                fw = sast_match.framework
                db_lib = sast_match.database_or_lib
            elif matched_source_content:
                # File exists in upload, but SAST did NOT find this vulnerability
                status = "NOT CONFIRMED IN CODE"
                confidence = "Medium (File Inspected, No Flaw Detected)"
                target_file = matched_source_file
                target_line = r_vuln.line_number or 1
                actual_code = "# Target file inspected; automated rules found no active flaw."
                lang = os.path.splitext(matched_source_file)[1].replace(".", "")
                fw = None
                db_lib = None
            else:
                # File not uploaded in source
                status = "UNVERIFIED (FILE NOT INCLUDED)"
                confidence = "Low (Source Code Not Provided)"
                target_file = r_vuln.file_name or "N/A"
                target_line = r_vuln.line_number or 1
                actual_code = r_vuln.evidence or "# Source file not available."
                lang = getattr(r_vuln, "language", None)
                fw = getattr(r_vuln, "framework", None)
                db_lib = None

            # Generate high-confidence AI remediation
            kb_desc = ""
            kb_rem = ""
            if r_cwe:
                kb_item = db.query(KnowledgeBaseItem).filter(KnowledgeBaseItem.cwe_id.ilike(r_cwe)).first()
                if kb_item:
                    kb_desc = kb_item.description or ""
                    kb_rem = kb_item.remediation or kb_item.recommendations or ""

            ai_res = generate_remediation(
                vulnerability=r_vuln.vulnerability_name,
                cwe_id=r_cwe,
                severity=r_vuln.severity,
                language=lang,
                framework=fw,
                database_or_lib=db_lib,
                file_name=target_file,
                line_number=target_line,
                vulnerable_code=actual_code,
                description=kb_desc,
                kb_remediation=kb_rem
            )

            correlated_results.append({
                "vulnerability": r_vuln.vulnerability_name,
                "cwe_id": r_cwe,
                "cve_id": getattr(r_vuln, "cve_id", None),
                "severity": r_vuln.severity,
                "correlation_status": status,
                "confidence": confidence,
                "language": ai_res.get("language", "Unknown"),
                "framework": ai_res.get("framework", "Unknown"),
                "file": target_file,
                "line": target_line,
                "vulnerable_code": actual_code,
                "why_vulnerable": ai_res.get("why_vulnerable"),
                "knowledge_base_remediation": kb_rem or getattr(r_vuln, "remediation", "Apply least privilege."),
                "ai_remediation": ai_res.get("ai_remediation"),
                "secure_code": ai_res.get("secure_code"),
                "implementation_steps": ai_res.get("implementation_steps", []),
                "verification_steps": ai_res.get("verification_steps", [])
            })

        # Also append SAST discoveries not mentioned in VAPT report
        for s_find in source_findings:
            if (s_find.file_name, s_find.line_number, s_find.cwe_id) not in matched_sast_keys:
                ai_res = generate_remediation(
                    vulnerability=s_find.vulnerability_name,
                    cwe_id=s_find.cwe_id,
                    severity=s_find.severity,
                    language=s_find.language,
                    framework=s_find.framework,
                    database_or_lib=s_find.database_or_lib,
                    file_name=s_find.file_name,
                    line_number=s_find.line_number,
                    vulnerable_code=s_find.matched_code or s_find.code_snippet,
                    description=s_find.description,
                    kb_remediation=s_find.remediation
                )
                correlated_results.append({
                    "vulnerability": s_find.vulnerability_name,
                    "cwe_id": s_find.cwe_id,
                    "cve_id": None,
                    "severity": s_find.severity,
                    "correlation_status": "ADDITIONAL SOURCE FINDING",
                    "confidence": "High (Direct Code SAST Detection)",
                    "language": ai_res.get("language", s_find.language),
                    "framework": ai_res.get("framework", s_find.framework or "Unknown"),
                    "file": s_find.file_name,
                    "line": s_find.line_number,
                    "vulnerable_code": s_find.matched_code or s_find.code_snippet,
                    "why_vulnerable": ai_res.get("why_vulnerable"),
                    "knowledge_base_remediation": s_find.remediation or "Apply input validation.",
                    "ai_remediation": ai_res.get("ai_remediation"),
                    "secure_code": ai_res.get("secure_code"),
                    "implementation_steps": ai_res.get("implementation_steps", []),
                    "verification_steps": ai_res.get("verification_steps", [])
                })

        confirmed_count = sum(1 for c in correlated_results if c["correlation_status"] == "CONFIRMED")

        return {
            "message": "Combined VAPT report and source code correlation completed.",
            "report_filename": report_filename,
            "source_filename": source_filename,
            "report_findings_count": len(report_vulns),
            "source_findings_count": len(source_findings),
            "confirmed_in_code_count": confirmed_count,
            "total_correlated_findings": len(correlated_results),
            "findings": correlated_results
        }

    finally:
        if temp_zip_dir:
            cleanup_directory(temp_zip_dir)
