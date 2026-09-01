import json
import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

from app.main import app
from app.schemas.evaluation import (
    GeminiEvaluationResult,
    VulnerabilityEvaluationItem,
    EvaluationMetrics
)
from app.services.evaluation_metrics import calculate_metrics
from app.services.gemini_evaluator import (
    clean_json_response,
    evaluate_vulnerability,
    evaluate_report_vulnerabilities
)


@pytest.fixture
def client():
    return TestClient(app)


# =========================================================
# 1. JSON Parsing & Sanitization Tests
# =========================================================

def test_clean_json_response_with_markdown_fences():
    raw_markdown = """```json
    {
        "vulnerability": "SQL Injection",
        "is_vulnerability_correct": true,
        "vulnerability_confidence": 0.95,
        "remediation_is_correct": true,
        "remediation_score": 0.90,
        "missing_points": ["Use WAF"],
        "gemini_recommended_remediation": "Use prepared statements",
        "reason": "Accurate detection",
        "severity_assessment": "High",
        "overall_correct": true
    }
    ```"""
    cleaned = clean_json_response(raw_markdown)
    parsed = json.loads(cleaned)
    assert parsed["vulnerability"] == "SQL Injection"
    assert parsed["is_vulnerability_correct"] is True


def test_clean_json_response_plain_json():
    plain = '{"vulnerability": "XSS", "is_vulnerability_correct": true}'
    assert clean_json_response(plain) == plain


# =========================================================
# 2. Metric Calculation Unit Tests
# =========================================================

def test_calculate_metrics_all_correct():
    items = [
        VulnerabilityEvaluationItem(
            vulnerability="SQL Injection",
            evaluation_status="success",
            gemini_evaluation=GeminiEvaluationResult(
                vulnerability="SQL Injection",
                is_vulnerability_correct=True,
                vulnerability_confidence=0.95,
                remediation_is_correct=True,
                remediation_score=1.0,
                missing_points=[],
                gemini_recommended_remediation="Parameterized queries",
                reason="Perfect remediation",
                severity_assessment="High",
                overall_correct=True
            )
        ),
        VulnerabilityEvaluationItem(
            vulnerability="Cross-Site Scripting (XSS)",
            evaluation_status="success",
            gemini_evaluation=GeminiEvaluationResult(
                vulnerability="Cross-Site Scripting (XSS)",
                is_vulnerability_correct=True,
                vulnerability_confidence=0.90,
                remediation_is_correct=True,
                remediation_score=0.80,
                missing_points=["Add CSP"],
                gemini_recommended_remediation="HTML encode inputs and outputs",
                reason="Sufficient remediation",
                severity_assessment="High",
                overall_correct=True
            )
        )
    ]
    
    metrics = calculate_metrics(items, total_report_vulnerabilities=2)
    assert metrics.total_vulnerabilities == 2
    assert metrics.evaluated_count == 2
    assert metrics.correct_vulnerabilities == 2
    assert metrics.incorrect_vulnerabilities == 0
    assert metrics.vulnerability_accuracy == 1.0
    assert metrics.remediation_accuracy == 1.0
    assert metrics.average_remediation_score == 0.90
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1_score == 1.0
    assert metrics.overall_accuracy == 1.0


def test_calculate_metrics_mixed_results():
    items = [
        VulnerabilityEvaluationItem(
            vulnerability="SQL Injection",
            evaluation_status="success",
            gemini_evaluation=GeminiEvaluationResult(
                vulnerability="SQL Injection",
                is_vulnerability_correct=True,
                vulnerability_confidence=0.95,
                remediation_is_correct=True,
                remediation_score=0.80,
                missing_points=[],
                gemini_recommended_remediation="Parameterized queries",
                reason="Good",
                severity_assessment="High",
                overall_correct=True
            )
        ),
        VulnerabilityEvaluationItem(
            vulnerability="False Positive Vuln",
            evaluation_status="success",
            gemini_evaluation=GeminiEvaluationResult(
                vulnerability="False Positive Vuln",
                is_vulnerability_correct=False,
                vulnerability_confidence=0.20,
                remediation_is_correct=False,
                remediation_score=0.20,
                missing_points=["Not a vulnerability"],
                gemini_recommended_remediation="No fix needed",
                reason="Invalid identification",
                severity_assessment="Low",
                overall_correct=False
            )
        )
    ]
    
    metrics = calculate_metrics(items, total_report_vulnerabilities=2)
    assert metrics.correct_vulnerabilities == 1
    assert metrics.incorrect_vulnerabilities == 1
    assert metrics.vulnerability_accuracy == 0.5
    assert metrics.remediation_accuracy == 0.5
    assert metrics.average_remediation_score == 0.50
    assert metrics.precision == 0.5
    assert metrics.recall == 0.5
    assert metrics.f1_score == 0.5
    assert metrics.overall_accuracy == 0.5


def test_calculate_metrics_empty_list():
    metrics = calculate_metrics([], total_report_vulnerabilities=0)
    assert metrics.total_vulnerabilities == 0
    assert metrics.evaluated_count == 0
    assert metrics.vulnerability_accuracy is None
    assert metrics.remediation_accuracy is None
    assert metrics.average_remediation_score is None
    assert metrics.precision is None
    assert metrics.recall is None
    assert metrics.f1_score is None
    assert metrics.overall_accuracy is None


def test_calculate_metrics_with_failed_items():
    items = [
        VulnerabilityEvaluationItem(
            vulnerability="Buffer Overflow",
            evaluation_status="failed",
            error_message="Rate limit exceeded",
            gemini_evaluation=None
        )
    ]
    metrics = calculate_metrics(items, total_report_vulnerabilities=1)
    assert metrics.total_vulnerabilities == 1
    assert metrics.evaluated_count == 0
    assert metrics.vulnerability_accuracy is None


# =========================================================
# 3. Mocked Gemini Evaluator Service Tests
# =========================================================

def test_evaluate_vulnerability_mocked():
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.text = json.dumps({
        "vulnerability": "SQL Injection",
        "is_vulnerability_correct": True,
        "vulnerability_confidence": 0.98,
        "remediation_is_correct": True,
        "remediation_score": 0.92,
        "missing_points": ["Least privilege DB user"],
        "gemini_recommended_remediation": "Use prepared statements and validate inputs",
        "reason": "Accurately identified and sound remediation",
        "severity_assessment": "High",
        "overall_correct": True
    })
    mock_client.models.generate_content.return_value = mock_response

    result = evaluate_vulnerability(
        vulnerability="SQL Injection",
        kb_remediation="Use parameterized queries",
        relevant_context="login.py:12",
        client=mock_client
    )

    assert result.vulnerability == "SQL Injection"
    assert result.is_vulnerability_correct is True
    assert result.remediation_score == 0.92
    assert "Least privilege DB user" in result.missing_points
    assert result.overall_correct is True


def test_evaluate_report_vulnerabilities_graceful_failure():
    mock_client = MagicMock()
    mock_client.models.generate_content.side_effect = Exception("Simulated Gemini API timeout")

    dummy_vuln = MagicMock()
    dummy_vuln.vulnerability_name = "XSS"
    dummy_vuln.cwe_id = "CWE-79"
    dummy_vuln.severity = "High"
    dummy_vuln.file_name = "app.js"
    dummy_vuln.line_number = 42
    dummy_vuln.remediation = "Encode outputs"

    results = evaluate_report_vulnerabilities([dummy_vuln], "report.pdf", client=mock_client)
    assert len(results) == 1
    assert results[0].evaluation_status == "failed"
    assert "Simulated Gemini API timeout" in results[0].error_message


def test_evaluate_report_vulnerabilities_missing_api_key():
    with patch("app.core.config.settings.GEMINI_API_KEY", ""):
        dummy_vuln = MagicMock()
        dummy_vuln.vulnerability_name = "SQL Injection"
        dummy_vuln.cwe_id = "CWE-89"
        dummy_vuln.severity = "High"
        dummy_vuln.file_name = "db.py"
        dummy_vuln.line_number = 10
        dummy_vuln.remediation = "Use ORM"

        results = evaluate_report_vulnerabilities([dummy_vuln], "report.pdf", client=None)
        assert len(results) == 1
        assert results[0].evaluation_status == "failed"
        assert "GEMINI_API_KEY is not configured" in results[0].error_message


# =========================================================
# 4. FastAPI Endpoint Integration Tests
# =========================================================

def test_get_evaluation_status(client):
    response = client.get("/evaluation/status")
    assert response.status_code == 200
    data = response.json()
    assert "configured" in data
    assert "model" in data
    assert "provider" in data
    assert data["provider"] == "Google GenAI SDK (google-genai)"


# =========================================================
# 5. Deduplication & Unique Location Tests
# =========================================================

def test_duplicate_vulnerability_removal():
    from app.services.pdf_parser import deduplicate_vulnerabilities

    class DummyVuln:
        def __init__(self, name, cwe, file_name, line):
            self.vulnerability_name = name
            self.cwe_id = cwe
            self.file_name = file_name
            self.line_number = line

    # 6 items with duplicates
    vuln_list = [
        DummyVuln("SQL Injection", "CWE-89", "N/A", 1),
        DummyVuln("SQL Injection", "CWE-89", "N/A", 1),
        DummyVuln("Cross-Site Scripting (XSS)", "CWE-79", "N/A", 1),
        DummyVuln("Cross-Site Scripting (XSS)", "CWE-79", "N/A", 1),
        DummyVuln("Buffer Overflow", "CWE-120", "N/A", 1),
        DummyVuln("Buffer Overflow", "CWE-120", "N/A", 1),
    ]

    unique_list = deduplicate_vulnerabilities(vuln_list)
    assert len(unique_list) == 3
    assert [v.vulnerability_name for v in unique_list] == [
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "Buffer Overflow"
    ]


def test_unique_findings_at_different_locations():
    from app.services.pdf_parser import deduplicate_vulnerabilities

    class DummyVuln:
        def __init__(self, name, cwe, file_name, line):
            self.vulnerability_name = name
            self.cwe_id = cwe
            self.file_name = file_name
            self.line_number = line

    # Same vulnerability type at different files / lines must NOT be removed
    vuln_list = [
        DummyVuln("SQL Injection", "CWE-89", "auth.py", 25),
        DummyVuln("SQL Injection", "CWE-89", "search.py", 110),
        DummyVuln("SQL Injection", "CWE-89", "auth.py", 25),  # duplicate of #1
        DummyVuln("XSS", "CWE-79", "views.js", 14),
    ]

    unique_list = deduplicate_vulnerabilities(vuln_list)
    assert len(unique_list) == 3
    assert (unique_list[0].file_name, unique_list[0].line_number) == ("auth.py", 25)
    assert (unique_list[1].file_name, unique_list[1].line_number) == ("search.py", 110)
    assert (unique_list[2].file_name, unique_list[2].line_number) == ("views.js", 14)


# =========================================================
# 6. Gemini 429 Quota Handling & Partial Evaluation Tests
# =========================================================

def test_gemini_429_quota_exhausted_handling():
    mock_client = MagicMock()
    mock_client.models.generate_content.side_effect = Exception("429 RESOURCE_EXHAUSTED: Quota exceeded for model")

    dummy_vulns = [
        MagicMock(vulnerability_name="SQL Injection", cwe_id="CWE-89", severity="High", file_name="N/A", line_number=1, remediation="Fix SQL"),
        MagicMock(vulnerability_name="XSS", cwe_id="CWE-79", severity="High", file_name="N/A", line_number=1, remediation="Fix XSS"),
    ]

    results = evaluate_report_vulnerabilities(dummy_vulns, "synthetic.pdf", client=mock_client)
    assert len(results) == 2
    for item in results:
        assert item.evaluation_status == "failed"
        assert "Gemini quota exceeded; this finding was not evaluated." in item.error_message

    # Verify generate_content was called only once and remaining items were batched gracefully
    assert mock_client.models.generate_content.call_count == 1


def test_zero_successful_evaluations():
    items = [
        VulnerabilityEvaluationItem(
            vulnerability="SQL Injection",
            evaluation_status="failed",
            error_message="Gemini quota exceeded; this finding was not evaluated."
        ),
        VulnerabilityEvaluationItem(
            vulnerability="XSS",
            evaluation_status="failed",
            error_message="Gemini quota exceeded; this finding was not evaluated."
        ),
        VulnerabilityEvaluationItem(
            vulnerability="Buffer Overflow",
            evaluation_status="failed",
            error_message="Gemini quota exceeded; this finding was not evaluated."
        ),
    ]

    metrics = calculate_metrics(items, total_report_vulnerabilities=3)
    assert metrics.total_findings == 3
    assert metrics.successfully_evaluated == 0
    assert metrics.failed_evaluations == 3
    assert metrics.evaluation_coverage == 0.0
    assert metrics.vulnerability_accuracy is None
    assert metrics.remediation_accuracy is None
    assert metrics.average_remediation_score is None
    assert metrics.precision is None
    assert metrics.recall is None
    assert metrics.f1_score is None
    assert metrics.overall_accuracy is None


def test_partial_evaluation_coverage_and_accuracy():
    # 2 out of 3 findings evaluated successfully and correctly, 1 failed due to 429
    items = [
        VulnerabilityEvaluationItem(
            vulnerability="SQL Injection",
            evaluation_status="success",
            gemini_evaluation=GeminiEvaluationResult(
                vulnerability="SQL Injection",
                is_vulnerability_correct=True,
                vulnerability_confidence=0.95,
                remediation_is_correct=True,
                remediation_score=0.90,
                missing_points=[],
                gemini_recommended_remediation="Parameterized queries",
                reason="Valid",
                severity_assessment="High",
                overall_correct=True
            )
        ),
        VulnerabilityEvaluationItem(
            vulnerability="XSS",
            evaluation_status="success",
            gemini_evaluation=GeminiEvaluationResult(
                vulnerability="XSS",
                is_vulnerability_correct=True,
                vulnerability_confidence=0.90,
                remediation_is_correct=True,
                remediation_score=0.85,
                missing_points=[],
                gemini_recommended_remediation="Encode output",
                reason="Valid",
                severity_assessment="High",
                overall_correct=True
            )
        ),
        VulnerabilityEvaluationItem(
            vulnerability="Buffer Overflow",
            evaluation_status="failed",
            error_message="Gemini quota exceeded; this finding was not evaluated.",
            gemini_evaluation=None
        ),
    ]

    metrics = calculate_metrics(items, total_report_vulnerabilities=3)
    assert metrics.total_findings == 3
    assert metrics.successfully_evaluated == 2
    assert metrics.failed_evaluations == 1
    assert metrics.evaluation_coverage == 0.6667  # 2/3 = 66.67%
    assert metrics.vulnerability_accuracy == 1.0   # 2/2 evaluated were correct = 100%
    assert metrics.remediation_accuracy == 1.0     # 2/2 evaluated were correct = 100%
    assert metrics.average_remediation_score == 0.875
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1_score == 1.0
    assert metrics.correct_vulnerabilities == 2
    assert metrics.incorrect_vulnerabilities == 0  # 429 was NOT counted as incorrect


def test_successful_3_of_3_evaluation_flow():
    items = [
        VulnerabilityEvaluationItem(
            vulnerability="SQL Injection",
            evaluation_status="success",
            gemini_evaluation=GeminiEvaluationResult(
                vulnerability="SQL Injection",
                is_vulnerability_correct=True,
                vulnerability_confidence=0.98,
                remediation_is_correct=True,
                remediation_score=0.95,
                missing_points=[],
                gemini_recommended_remediation="Parameterized queries",
                reason="Valid",
                severity_assessment="High",
                overall_correct=True
            )
        ),
        VulnerabilityEvaluationItem(
            vulnerability="Cross-Site Scripting (XSS)",
            evaluation_status="success",
            gemini_evaluation=GeminiEvaluationResult(
                vulnerability="Cross-Site Scripting (XSS)",
                is_vulnerability_correct=True,
                vulnerability_confidence=0.92,
                remediation_is_correct=True,
                remediation_score=0.90,
                missing_points=[],
                gemini_recommended_remediation="HTML encoding",
                reason="Valid",
                severity_assessment="High",
                overall_correct=True
            )
        ),
        VulnerabilityEvaluationItem(
            vulnerability="Buffer Overflow",
            evaluation_status="success",
            gemini_evaluation=GeminiEvaluationResult(
                vulnerability="Buffer Overflow",
                is_vulnerability_correct=True,
                vulnerability_confidence=0.90,
                remediation_is_correct=True,
                remediation_score=0.85,
                missing_points=[],
                gemini_recommended_remediation="Use strncpy",
                reason="Valid",
                severity_assessment="Critical",
                overall_correct=True
            )
        ),
    ]

    metrics = calculate_metrics(items, total_report_vulnerabilities=3)
    assert metrics.total_findings == 3
    assert metrics.successfully_evaluated == 3
    assert metrics.failed_evaluations == 0
    assert metrics.evaluation_coverage == 1.0
    assert metrics.vulnerability_accuracy == 1.0
    assert metrics.remediation_accuracy == 1.0
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1_score == 1.0


# =========================================================
# 7. FastAPI Endpoint Integration Tests
# =========================================================

def test_evaluate_report_rejects_non_pdf(client):
    response = client.post(
        "/evaluate-report",
        files={"file": ("test.txt", b"Hello world", "text/plain")}
    )
    assert response.status_code == 400
    assert "Only PDF files are allowed" in response.json()["detail"]


def test_evaluate_report_endpoint_full_flow(client):
    with patch("app.services.gemini_evaluator.get_gemini_client") as mock_get_client:
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.text = json.dumps({
            "vulnerability": "SQL Injection (CWE-89)",
            "is_vulnerability_correct": True,
            "vulnerability_confidence": 0.96,
            "remediation_is_correct": True,
            "remediation_score": 0.90,
            "missing_points": ["Input allowlisting"],
            "gemini_recommended_remediation": "Use parameterized queries and ORM securely.",
            "reason": "Correct identification and valid remediation.",
            "severity_assessment": "High",
            "overall_correct": True
        })
        mock_client.models.generate_content.return_value = mock_response
        mock_get_client.return_value = mock_client

        # Upload the sample PDF located in backend/uploads
        sample_path = "uploads/sample_vapt_report.pdf"
        with open(sample_path, "rb") as f:
            pdf_bytes = f.read()

        response = client.post(
            "/evaluate-report",
            files={"file": ("sample_vapt_report.pdf", pdf_bytes, "application/pdf")}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["report_name"] == "sample_vapt_report.pdf"
        assert "metrics" in data
        assert "vulnerability_accuracy" in data["metrics"]
        assert "precision" in data["metrics"]
        assert "recall" in data["metrics"]
        assert "f1_score" in data["metrics"]
        assert "evaluation_coverage" in data["metrics"]
        assert len(data["evaluations"]) > 0
        assert data["evaluations"][0]["gemini_evaluation"]["is_vulnerability_correct"] is True
