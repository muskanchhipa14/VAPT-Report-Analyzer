import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.core.database import SessionLocal, get_db
from app.services.ai_remediation_service import generate_remediation
from app.source_scanner.scanner import scan_single_file_content
from app.services.pdf_parser import parse_vapt_text
from app.services.correlation_service import correlate_report_and_code

client = TestClient(app)


def test_python_source_code_remediation():
    """
    Python code with SQL injection should produce Python-specific parameterized query fix (%s / tuple),
    not Java PreparedStatement or other language syntax.
    """
    python_code = """
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()
"""
    result = scan_single_file_content(python_code, filename="login.py", language="python")
    assert result is not None
    assert len(result.findings) >= 1

    finding = result.findings[0]
    assert finding.cwe_id == "CWE-89"
    assert finding.language.lower() == "python"

    # AI Remediation Verification
    remediation = generate_remediation(
        vulnerability=finding.vulnerability_name,
        cwe_id=finding.cwe_id,
        severity=finding.severity,
        language="python",
        file_name="login.py",
        line_number=finding.line_number,
        vulnerable_code=finding.matched_code
    )

    assert remediation["cwe_id"] == "CWE-89"
    assert remediation["language"].lower() == "python"
    assert "why_vulnerable" in remediation
    assert "ai_remediation" in remediation
    assert "secure_code" in remediation
    assert len(remediation["implementation_steps"]) > 0
    assert len(remediation["verification_steps"]) > 0

    # Must contain Python-specific parameterized syntax, NOT Java PreparedStatement
    assert "%s" in remediation["secure_code"] or "cursor.execute" in remediation["secure_code"] or "SQLAlchemy" in remediation["secure_code"]
    assert "PreparedStatement" not in remediation["secure_code"]


def test_java_source_code_remediation():
    """
    Java code with SQL injection must produce Java PreparedStatement remediation,
    NOT Python or PHP remediation.
    """
    java_code = """
package com.example.dao;
import java.sql.*;

public class UserDao {
    public ResultSet getUser(Connection conn, String userId) throws SQLException {
        String sql = "SELECT * FROM users WHERE id = '" + userId + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(sql);
    }
}
"""
    result = scan_single_file_content(java_code, filename="UserDao.java", language="java")
    assert result is not None
    assert len(result.findings) >= 1

    finding = result.findings[0]
    assert finding.cwe_id == "CWE-89"
    assert finding.language.lower() == "java"

    # AI Remediation Verification
    remediation = generate_remediation(
        vulnerability=finding.vulnerability_name,
        cwe_id=finding.cwe_id,
        severity=finding.severity,
        language="java",
        file_name="UserDao.java",
        line_number=finding.line_number,
        vulnerable_code=finding.matched_code
    )

    assert remediation["cwe_id"] == "CWE-89"
    assert remediation["language"].lower() == "java"
    # Must contain Java-specific PreparedStatement, NOT Python cursor.execute
    assert "PreparedStatement" in remediation["secure_code"]
    assert "pstmt.setString" in remediation["secure_code"]
    assert "cursor.execute" not in remediation["secure_code"]


def test_javascript_dom_xss_remediation():
    """
    JavaScript code with DOM XSS should produce JS/React-specific remediation (DOMPurify or JSX text).
    """
    js_code = """
function renderProfile(userBio) {
    const container = document.getElementById("bio");
    container.innerHTML = userBio;
}
"""
    result = scan_single_file_content(js_code, filename="profile.js", language="javascript")
    assert result is not None
    assert len(result.findings) >= 1

    finding = result.findings[0]
    assert finding.cwe_id == "CWE-79"
    assert finding.language.lower() == "javascript"

    remediation = generate_remediation(
        vulnerability=finding.vulnerability_name,
        cwe_id=finding.cwe_id,
        severity=finding.severity,
        language="javascript",
        file_name="profile.js",
        line_number=finding.line_number,
        vulnerable_code=finding.matched_code
    )

    assert remediation["cwe_id"] == "CWE-79"
    assert "DOMPurify" in remediation["secure_code"] or "auto-escape" in remediation["ai_remediation"] or "textContent" in remediation["ai_remediation"]


def test_c_buffer_overflow_remediation():
    """
    C code with strcpy should detect CWE-120 Buffer Overflow and produce C bounds-checked fix (strncpy_s / snprintf).
    """
    c_code = """
#include <stdio.h>
#include <string.h>

void process_input(const char *input) {
    char buffer[64];
    strcpy(buffer, input);
}
"""
    result = scan_single_file_content(c_code, filename="buffer.c", language="c")
    assert result is not None
    assert len(result.findings) >= 1

    finding = result.findings[0]
    assert finding.cwe_id == "CWE-120"
    assert finding.language.lower() == "c"

    remediation = generate_remediation(
        vulnerability=finding.vulnerability_name,
        cwe_id=finding.cwe_id,
        severity=finding.severity,
        language="c",
        file_name="buffer.c",
        line_number=finding.line_number,
        vulnerable_code=finding.matched_code
    )

    assert remediation["cwe_id"] == "CWE-120"
    assert "snprintf" in remediation["secure_code"] or "strncpy" in remediation["secure_code"]


def test_php_sqli_remediation():
    """
    PHP code with mysqli_query should detect CWE-89 and produce PHP PDO prepared statement.
    """
    php_code = """
<?php
$conn = mysqli_connect("localhost", "root", "", "test");
$userId = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $userId;
$result = mysqli_query($conn, $query);
?>
"""
    result = scan_single_file_content(php_code, filename="get_user.php", language="php")
    assert result is not None
    assert len(result.findings) >= 1

    finding = result.findings[0]
    assert finding.cwe_id == "CWE-89"
    assert finding.language.lower() == "php"

    remediation = generate_remediation(
        vulnerability=finding.vulnerability_name,
        cwe_id=finding.cwe_id,
        severity=finding.severity,
        language="php",
        file_name="get_user.php",
        line_number=finding.line_number,
        vulnerable_code=finding.matched_code
    )

    assert remediation["cwe_id"] == "CWE-89"
    assert "$pdo->prepare" in remediation["secure_code"] or "$stmt" in remediation["secure_code"]


def test_csharp_sqli_remediation():
    """
    C# code with SqlCommand should detect CWE-89 and produce C# Parameters.AddWithValue fix.
    """
    cs_code = """
using System;
using System.Data.SqlClient;

public class UserService {
    public void FindUser(string userId, SqlConnection conn) {
        string query = "SELECT * FROM Users WHERE Id = " + userId;
        SqlCommand cmd = new SqlCommand(query, conn);
        SqlDataReader reader = cmd.ExecuteReader();
    }
}
"""
    result = scan_single_file_content(cs_code, filename="UserService.cs", language="csharp")
    assert result is not None
    assert len(result.findings) >= 1

    finding = result.findings[0]
    assert finding.cwe_id == "CWE-89"
    assert finding.language.lower() == "csharp"

    remediation = generate_remediation(
        vulnerability=finding.vulnerability_name,
        cwe_id=finding.cwe_id,
        severity=finding.severity,
        language="csharp",
        file_name="UserService.cs",
        line_number=finding.line_number,
        vulnerable_code=finding.matched_code
    )

    assert remediation["cwe_id"] == "CWE-89"
    assert "@" in remediation["secure_code"] or "Parameters" in remediation["secure_code"]


def test_go_sqli_remediation():
    """
    Go code with db.Query and fmt.Sprintf should detect CWE-89 and produce Go parameterized query.
    """
    go_code = """
package main

import (
    "database/sql"
    "fmt"
)

func QueryUser(db *sql.DB, id string) (*sql.Rows, error) {
    query := fmt.Sprintf("SELECT id, name FROM users WHERE id = '%s'", id)
    return db.Query(query)
}
"""
    result = scan_single_file_content(go_code, filename="query.go", language="go")
    assert result is not None
    assert len(result.findings) >= 1

    finding = result.findings[0]
    assert finding.cwe_id == "CWE-89"
    assert finding.language.lower() == "go"

    remediation = generate_remediation(
        vulnerability=finding.vulnerability_name,
        cwe_id=finding.cwe_id,
        severity=finding.severity,
        language="go",
        file_name="query.go",
        line_number=finding.line_number,
        vulnerable_code=finding.matched_code
    )

    assert remediation["cwe_id"] == "CWE-89"
    assert "$1" in remediation["secure_code"] or "db.Query" in remediation["secure_code"]


def test_unknown_language_handling():
    """
    Section 10 Safety Rule: When language cannot be determined, system must NOT invent
    a language-specific code fix or hallucinate.
    """
    remediation = generate_remediation(
        vulnerability="SQL Injection",
        cwe_id="CWE-89",
        severity="High",
        language=None,
        file_name="unidentified_binary.dat"
    )

    assert remediation["language"] == "Unknown"
    assert "Insufficient evidence" in remediation["ai_remediation"] or "could not be determined" in remediation["why_vulnerable"]


def test_vapt_report_text_parsing_flow():
    """
    Flow 1: VAPT report in text format extracts CWE-89, retrieves KB info, and attaches AI remediation.
    """
    report_text = """
SECURITY ASSESSMENT REPORT
==========================
Target System: Order Management API
Date: 2026-09-01

Finding 1: SQL Injection
Severity: High
CWE-89
CVE-2023-45678
Affected Component: app/core/database.py line: 42
Evidence:
query = "SELECT * FROM orders WHERE user_id = " + req.get("user_id")

Finding 2: Cross-Site Scripting (XSS)
Severity: High
CWE-79
Affected Component: templates/profile.html line: 15
"""
    findings = parse_vapt_text(report_text, report_name="pentest_order_api.txt")
    assert len(findings) >= 2

    sqli = next((f for f in findings if f.cwe_id == "CWE-89"), None)
    assert sqli is not None
    assert sqli.vulnerability_name == "SQL Injection"
    assert sqli.file_name == "app/core/database.py"
    assert sqli.line_number == 42
    assert sqli.cve_id == "CVE-2023-45678"
    assert sqli.why_vulnerable is not None
    assert sqli.ai_remediation is not None
    assert sqli.secure_code is not None


def test_combined_correlation_flow():
    """
    Flow 3: VAPT report + Source code combined.
    Correlates reported CWE-89 in login.py with actual python code.
    Verifies that status is CONFIRMED with high confidence.
    """
    report_text = """
Vulnerability Assessment
Target File: login.py line: 10
Issue: SQL Injection
CWE-89
Severity: High
"""
    vulnerable_py_code = """
import sqlite3

def login(user_id):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE id=" + user_id
    cur.execute(query)
"""
    db = SessionLocal()
    try:
        corr_result = correlate_report_and_code(
            report_path=report_text,
            report_filename="vapt_scan.txt",
            source_path_or_content=vulnerable_py_code,
            source_filename="login.py",
            db=db,
            is_source_content=True
        )

        assert corr_result["confirmed_in_code_count"] >= 1
        finding = corr_result["findings"][0]
        assert finding["correlation_status"] == "CONFIRMED"
        assert "Verified against Source Code" in finding["confidence"]
        assert finding["cwe_id"] == "CWE-89"
        assert finding["language"].lower() == "python"
        assert "%s" in finding["secure_code"] or "cursor.execute" in finding["secure_code"]
    finally:
        db.close()


def test_api_remediation_generate_endpoint():
    """
    Tests POST /api/remediation/generate REST endpoint.
    """
    payload = {
        "vulnerability": "Command Injection",
        "cwe_id": "CWE-78",
        "severity": "Critical",
        "language": "python",
        "file_name": "backup.py",
        "line_number": 25,
        "vulnerable_code": "os.system('tar -czf ' + filename)"
    }
    response = client.post("/api/remediation/generate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["cwe_id"] == "CWE-78"
    assert data["language"].lower() == "python"
    assert "subprocess.run" in data["secure_code"] or "shell=False" in data["secure_code"]


def test_api_analyze_source_code_pasted():
    """
    Tests POST /api/analyze/source-code with pasted source code.
    """
    py_code = 'query = "SELECT * FROM items WHERE name = \'" + user_input + "\'"\ncursor.execute(query)'
    response = client.post(
        "/api/analyze/source-code",
        data={
            "code_content": py_code,
            "filename": "search.py",
            "language": "python"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["vulnerabilities_found"] >= 1
    finding = data["findings"][0]
    assert finding["cwe_id"] == "CWE-89"
    assert finding["language"].lower() == "python"
    assert "secure_code" in finding
