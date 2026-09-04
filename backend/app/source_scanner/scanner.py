"""
Source Code Scanner Coordinator
Walks directory, detects languages, runs static rules, enriches with Knowledge Base,
and returns aggregated results.
"""

import os
from typing import List, Optional
from sqlalchemy.orm import Session

from app.source_scanner.models import ScanFinding, FileScanResult, ScanSummary
from app.source_scanner.language_detector import (
    detect_language,
    is_binary_file,
    is_ignored_directory,
    should_skip_path
)
from app.source_scanner.languages.python_rules import scan_python_code
from app.source_scanner.languages.javascript_rules import scan_javascript_code
from app.source_scanner.languages.java_rules import scan_java_code
from app.models.knowledge_base import KnowledgeBaseItem


def enrich_finding_with_kb(finding: ScanFinding, db: Optional[Session] = None):
    """
    Enriches finding with Knowledge Base description, remediation, recommendations,
    and OWASP category if available.
    """
    if not db or not finding.cwe_id:
        return

    kb_item = db.query(KnowledgeBaseItem).filter(
        KnowledgeBaseItem.cwe_id.ilike(finding.cwe_id.strip())
    ).first()

    if not kb_item:
        kb_item = db.query(KnowledgeBaseItem).filter(
            KnowledgeBaseItem.vulnerability_name.ilike(finding.vulnerability_name)
        ).first()

    if kb_item:
        finding.description = kb_item.description
        finding.remediation = kb_item.remediation or kb_item.recommendations
        finding.recommendation = kb_item.recommendations or kb_item.remediation
        finding.owasp_category = kb_item.owasp_category or finding.owasp_category
        if kb_item.severity and not finding.severity:
            finding.severity = kb_item.severity


def scan_file(
    file_path: str,
    base_dir: Optional[str] = None,
    db: Optional[Session] = None
) -> Optional[FileScanResult]:
    """
    Scans a single source file and returns FileScanResult.
    """
    language = detect_language(file_path)
    if not language:
        return None

    if is_binary_file(file_path):
        return None

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception:
        return None

    lines = content.splitlines()
    line_count = len(lines)

    # Compute clean relative display path
    display_path = file_path
    if base_dir:
        try:
            display_path = os.path.relpath(file_path, base_dir).replace("\\", "/")
        except Exception:
            display_path = os.path.basename(file_path)

    findings: List[ScanFinding] = []

    if language == "python":
        findings = scan_python_code(display_path, content)
    elif language == "javascript":
        findings = scan_javascript_code(display_path, content)
    elif language == "java":
        findings = scan_java_code(display_path, content)

    # Enrich findings from Knowledge Base
    for finding in findings:
        enrich_finding_with_kb(finding, db)

    return FileScanResult(
        file_path=display_path,
        language=language,
        line_count=line_count,
        findings=findings
    )


def scan_directory(dir_path: str, db: Optional[Session] = None) -> ScanSummary:
    """
    Recursively scans directory for supported source files and computes summary.
    """
    summary = ScanSummary()
    abs_root = os.path.abspath(dir_path)

    for root, dirs, files in os.walk(abs_root, topdown=True):
        # Prune ignored directories in-place
        dirs[:] = [d for d in dirs if not is_ignored_directory(d) and not should_skip_path(os.path.join(root, d))]

        for file in files:
            file_abs = os.path.join(root, file)
            if should_skip_path(file_abs):
                continue

            result = scan_file(file_abs, base_dir=abs_root, db=db)
            if result:
                summary.files_scanned += 1
                summary.lines_scanned += result.line_count

                # Track languages
                lang_name = result.language.capitalize()
                summary.language_counts[lang_name] = summary.language_counts.get(lang_name, 0) + 1

                for finding in result.findings:
                    summary.findings.append(finding)
                    summary.vulnerabilities_found += 1

                    # Count severity
                    sev = finding.severity.capitalize() if finding.severity else "Medium"
                    if sev in summary.severity_counts:
                        summary.severity_counts[sev] += 1
                    else:
                        summary.severity_counts["Medium"] += 1

    return summary
