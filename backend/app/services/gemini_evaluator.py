import json
import logging
import re
from typing import Optional, List, Dict, Any

from google import genai
from google.genai import types
from google.genai.errors import APIError

from app.core.config import settings
from app.schemas.evaluation import GeminiEvaluationResult, VulnerabilityEvaluationItem

logger = logging.getLogger("gemini_evaluator")
logging.basicConfig(level=logging.INFO)

EVALUATOR_SYSTEM_INSTRUCTION = (
    "You are an expert cybersecurity VAPT reviewer.\n\n"
    "Your task is to independently evaluate the vulnerability and remediation produced by another VAPT analysis system.\n\n"
    "Do not automatically agree with the provided answer.\n\n"
    "Analyze whether:\n"
    "1. The vulnerability identification is technically valid.\n"
    "2. The proposed remediation actually addresses that vulnerability.\n"
    "3. The remediation follows accepted cybersecurity best practices.\n"
    "4. Important remediation steps are missing.\n"
    "5. The remediation contains technically incorrect or unsafe recommendations.\n\n"
    "Return an objective evaluation.\n\n"
    "If the evidence is insufficient, clearly indicate uncertainty.\n\n"
    "Do not invent CVEs, vulnerabilities, technologies, versions, or remediation requirements that are not supported by the provided information.\n\n"
    "Return ONLY valid JSON matching this schema:\n"
    "{\n"
    '  "vulnerability": "<name of vulnerability>",\n'
    '  "is_vulnerability_correct": true,\n'
    '  "vulnerability_confidence": 0.95,\n'
    '  "remediation_is_correct": true,\n'
    '  "remediation_score": 0.90,\n'
    '  "missing_points": ["point 1", "point 2"],\n'
    '  "gemini_recommended_remediation": "<comprehensive remediation>",\n'
    '  "reason": "<technical evaluation rationale>",\n'
    '  "severity_assessment": "High",\n'
    '  "overall_correct": true\n'
    "}"
)


def get_gemini_client() -> genai.Client:
    """Instantiates the google-genai client using configured API key."""
    if not settings.is_gemini_configured:
        raise ValueError(
            "GEMINI_API_KEY is not configured in environment variables or .env file. "
            "Please set GEMINI_API_KEY to enable AI evaluation."
        )
    return genai.Client(api_key=settings.GEMINI_API_KEY)


def clean_json_response(raw_text: str) -> str:
    """Strips markdown backticks and extracts pure JSON substring if necessary."""
    text = raw_text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    # Find outer JSON curly braces
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return text[start : end + 1]
    return text


def evaluate_vulnerability(
    vulnerability: str,
    kb_remediation: str,
    relevant_context: Optional[str] = None,
    client: Optional[genai.Client] = None,
    model_override: Optional[str] = None
) -> GeminiEvaluationResult:
    """
    Sends a single vulnerability detection and Knowledge Base remediation to Gemini
    for independent cybersecurity evaluation.
    """
    logger.info(f"Gemini evaluation request started for vulnerability: '{vulnerability}'")
    
    if client is None:
        client = get_gemini_client()

    model_name = model_override or settings.GEMINI_MODEL

    user_prompt = (
        f"VULNERABILITY:\n{vulnerability}\n\n"
        f"KNOWLEDGE BASE REMEDIATION:\n{kb_remediation}\n\n"
        f"OPTIONAL CONTEXT:\n{relevant_context or 'N/A'}\n"
    )

    config = types.GenerateContentConfig(
        system_instruction=EVALUATOR_SYSTEM_INSTRUCTION,
        response_mime_type="application/json",
        response_schema=GeminiEvaluationResult,
        temperature=0.2,
    )

    try:
        response = client.models.generate_content(
            model=model_name,
            contents=user_prompt,
            config=config,
        )
        
        logger.info(f"Gemini response received for vulnerability: '{vulnerability}'")
        
        response_text = response.text or ""
        cleaned_json = clean_json_response(response_text)
        
        parsed_data = json.loads(cleaned_json)
        
        # Ensure confidence and remediation scores are bounded between 0.0 and 1.0
        parsed_data["vulnerability_confidence"] = max(0.0, min(1.0, float(parsed_data.get("vulnerability_confidence", 0.0))))
        parsed_data["remediation_score"] = max(0.0, min(1.0, float(parsed_data.get("remediation_score", 0.0))))
        if not isinstance(parsed_data.get("missing_points"), list):
            parsed_data["missing_points"] = []
            
        result = GeminiEvaluationResult(**parsed_data)
        logger.info(f"Evaluation parsed successfully: overall_correct={result.overall_correct}, score={result.remediation_score}")
        return result

    except json.JSONDecodeError as jde:
        logger.error(f"JSON parsing failure from Gemini response for '{vulnerability}': {jde}")
        raise ValueError(f"Failed to parse structured JSON from Gemini evaluation: {str(jde)}")
    except APIError as ae:
        logger.error(f"Google Gemini API error during evaluation of '{vulnerability}': {ae}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error during Gemini evaluation of '{vulnerability}': {e}")
        raise


def is_quota_or_rate_limit_error(exc: Exception) -> bool:
    """Detects whether an exception represents a 429 rate limit or quota exhaustion."""
    err_str = str(exc).upper()
    return (
        "429" in err_str
        or "RESOURCE_EXHAUSTED" in err_str
        or "QUOTA" in err_str
        or "RATE_LIMIT" in err_str
        or "RATE LIMIT" in err_str
    )


def evaluate_report_vulnerabilities(
    detected_vulns: List[Any],
    report_name: str,
    client: Optional[genai.Client] = None
) -> List[VulnerabilityEvaluationItem]:
    """
    Evaluates a collection of detected vulnerabilities for a given report.
    Deduplicates findings first, and handles per-vulnerability errors gracefully.
    When a 429 RESOURCE_EXHAUSTED quota error is encountered, subsequent calls
    in the batch are gracefully flagged without flooding the API.
    """
    from app.services.pdf_parser import deduplicate_vulnerabilities

    # Ensure unique findings only
    unique_vulns = deduplicate_vulnerabilities(detected_vulns)
    evaluations: List[VulnerabilityEvaluationItem] = []

    if not unique_vulns:
        logger.info(f"No vulnerabilities found to evaluate for report '{report_name}'")
        return evaluations

    # Attempt to initialize client once; if API key is missing, fail gracefully across items
    try:
        if client is None:
            client = get_gemini_client()
    except Exception as init_err:
        logger.warning(f"Could not initialize Gemini Client: {init_err}")
        client = None

    rate_limit_exceeded = False
    quota_error_msg = "Gemini quota exceeded; this finding was not evaluated."

    for v in unique_vulns:
        vuln_name = getattr(v, "vulnerability_name", str(v))
        cwe_id = getattr(v, "cwe_id", "N/A")
        severity = getattr(v, "severity", "Medium")
        file_name = getattr(v, "file_name", "N/A")
        line_number = getattr(v, "line_number", 1)
        kb_remediation = getattr(v, "remediation", "No remediation available in Knowledge Base.")
        context = f"Report: {report_name}, File: {file_name}:{line_number}, Severity: {severity}, CWE: {cwe_id}"

        item = VulnerabilityEvaluationItem(
            vulnerability=vuln_name,
            cwe_id=cwe_id,
            severity=severity,
            file_name=file_name,
            line_number=line_number,
            knowledge_base_remediation=kb_remediation,
            evaluation_status="pending"
        )

        if client is None:
            item.evaluation_status = "failed"
            item.error_message = (
                "GEMINI_API_KEY is not configured. Please add GEMINI_API_KEY to .env to enable evaluations."
            )
            evaluations.append(item)
            continue

        if rate_limit_exceeded:
            item.evaluation_status = "failed"
            item.error_message = quota_error_msg
            evaluations.append(item)
            continue

        try:
            gemini_result = evaluate_vulnerability(
                vulnerability=f"{vuln_name} ({cwe_id})",
                kb_remediation=kb_remediation,
                relevant_context=context,
                client=client
            )
            item.gemini_evaluation = gemini_result
            item.evaluation_status = "success"
        except Exception as e:
            if is_quota_or_rate_limit_error(e):
                rate_limit_exceeded = True
                item.evaluation_status = "failed"
                item.error_message = quota_error_msg
                logger.warning(f"Gemini quota exceeded during evaluation of '{vuln_name}': {e}")
            else:
                item.evaluation_status = "failed"
                item.error_message = f"Evaluation failed: {str(e)}"
                logger.error(f"Evaluation failed for item '{vuln_name}': {e}")

        evaluations.append(item)

    logger.info(f"Completed evaluation of {len(evaluations)} items for report '{report_name}'")
    return evaluations
