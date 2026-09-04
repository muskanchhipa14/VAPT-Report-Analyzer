import os
import zipfile
import io
import pytest
from app.source_scanner.scanner import scan_file, scan_directory
from app.source_scanner.utils import safe_extract_zip, ZipSecurityError
from app.services.report_generator import generate_source_code_pdf_report
from app.core.database import SessionLocal
from app.services.knowledge_base import seed_knowledge_base

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


@pytest.fixture(scope="module")
def db():
    session = SessionLocal()
    seed_knowledge_base(session)
    yield session
    session.close()


def test_python_scanner(db):
    py_path = os.path.join(FIXTURES_DIR, "vulnerable_python.py")
    result = scan_file(py_path, base_dir=FIXTURES_DIR, db=db)

    assert result is not None
    assert result.language == "python"
    assert result.line_count > 20

    cwes = {f.cwe_id for f in result.findings}
    # Check all key CWEs are detected in Python
    assert "CWE-89" in cwes   # SQL Injection
    assert "CWE-78" in cwes   # Command Injection
    assert "CWE-502" in cwes  # Insecure Deserialization
    assert "CWE-327" in cwes  # Weak Crypto
    assert "CWE-798" in cwes  # Hardcoded Secret
    assert "CWE-22" in cwes   # Path Traversal
    assert "CWE-918" in cwes  # SSRF
    assert "CWE-330" in cwes  # Insecure Randomness
    assert "CWE-489" in cwes  # Debug Configuration

    # Check that findings have snippets and KB recommendations
    for f in result.findings:
        assert f.code_snippet != ""
        assert f.suggested_fix is not None


def test_javascript_scanner(db):
    js_path = os.path.join(FIXTURES_DIR, "vulnerable_javascript.js")
    result = scan_file(js_path, base_dir=FIXTURES_DIR, db=db)

    assert result is not None
    assert result.language == "javascript"

    cwes = {f.cwe_id for f in result.findings}
    assert "CWE-79" in cwes    # XSS (both innerHTML and dangerouslySetInnerHTML)
    assert "CWE-78" in cwes    # Command Injection (child_process.exec)
    assert "CWE-89" in cwes    # SQL Injection
    assert "CWE-798" in cwes   # Hardcoded Secret
    assert "CWE-1321" in cwes  # Prototype Pollution
    assert "CWE-22" in cwes    # Path Traversal
    assert "CWE-918" in cwes   # SSRF
    assert "CWE-327" in cwes   # Weak Cryptography (md5)


def test_java_scanner(db):
    java_path = os.path.join(FIXTURES_DIR, "vulnerable_java.java")
    result = scan_file(java_path, base_dir=FIXTURES_DIR, db=db)

    assert result is not None
    assert result.language == "java"

    cwes = {f.cwe_id for f in result.findings}
    assert "CWE-89" in cwes   # SQL Injection
    assert "CWE-78" in cwes   # Command Injection
    assert "CWE-611" in cwes  # XXE
    assert "CWE-22" in cwes   # Path Traversal
    assert "CWE-502" in cwes  # Insecure Deserialization
    assert "CWE-327" in cwes  # Weak Cryptography
    assert "CWE-798" in cwes  # Hardcoded Credentials


def test_safe_code_no_false_positives(db):
    safe_path = os.path.join(FIXTURES_DIR, "safe_code.py")
    result = scan_file(safe_path, base_dir=FIXTURES_DIR, db=db)

    assert result is not None
    # Parameterized SQL, secrets token, safe subprocess, safe sha256 should NOT trigger findings
    assert len(result.findings) == 0


def test_zip_slip_security(tmp_path):
    """Verifies that Zip Slip path traversal archives are strictly rejected."""
    bad_zip_path = tmp_path / "malicious.zip"
    extract_target = tmp_path / "extracted"

    # Create archive with path traversal entry
    with zipfile.ZipFile(bad_zip_path, "w") as zf:
        zf.writestr("../../etc/passwd", "root:x:0:0:root:/root:/bin/bash")

    with pytest.raises(ZipSecurityError):
        safe_extract_zip(str(bad_zip_path), str(extract_target))


def test_scan_directory(db):
    summary = scan_directory(FIXTURES_DIR, db=db)
    assert summary.files_scanned >= 4
    assert summary.lines_scanned > 50
    assert summary.vulnerabilities_found > 15
    assert summary.severity_counts["Critical"] > 0
    assert summary.severity_counts["High"] > 0


def test_pdf_report_generation(db):
    summary = scan_directory(FIXTURES_DIR, db=db)
    analysis_meta = {
        "project_name": "Test Project",
        "filename": "project.zip",
        "files_scanned": summary.files_scanned,
        "lines_scanned": summary.lines_scanned,
        "vulnerabilities_count": summary.vulnerabilities_found
    }

    pdf_buffer = generate_source_code_pdf_report(analysis_meta, summary.findings, db)
    pdf_bytes = pdf_buffer.getvalue()

    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF")
