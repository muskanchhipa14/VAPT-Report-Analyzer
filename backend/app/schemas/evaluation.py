from typing import List, Optional
from pydantic import BaseModel, Field


class GeminiEvaluationResult(BaseModel):
    """Structured output returned directly by Gemini evaluator."""
    vulnerability: str = Field(description="Name or title of the vulnerability evaluated")
    is_vulnerability_correct: bool = Field(description="Whether the vulnerability was correctly identified in context")
    vulnerability_confidence: float = Field(ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0")
    remediation_is_correct: bool = Field(description="Whether the Knowledge Base remediation corresponds and is technically correct")
    remediation_score: float = Field(ge=0.0, le=1.0, description="Score from 0.0 to 1.0 representing completeness and accuracy of remediation")
    missing_points: List[str] = Field(default_factory=list, description="Crucial remediation steps or nuances omitted from KB remediation")
    gemini_recommended_remediation: str = Field(description="Gemini's recommended comprehensive remediation guidance")
    reason: str = Field(description="Technical rationale explaining the evaluation decisions")
    severity_assessment: str = Field(default="Medium", description="Gemini's assessed severity (Critical, High, Medium, Low, Info)")
    overall_correct: bool = Field(description="Overall determination if both detection and remediation are acceptable")


class VulnerabilityEvaluationItem(BaseModel):
    """Container for each evaluated vulnerability in a report."""
    vulnerability: str
    cwe_id: Optional[str] = None
    severity: Optional[str] = None
    file_name: Optional[str] = None
    line_number: Optional[int] = None
    knowledge_base_remediation: Optional[str] = None
    evaluation_status: str = Field(default="success", description="'success', 'failed', or 'skipped'")
    error_message: Optional[str] = None
    gemini_evaluation: Optional[GeminiEvaluationResult] = None


class EvaluationMetrics(BaseModel):
    """Computed evaluation and accuracy metrics."""
    total_findings: int = 0
    successfully_evaluated: int = 0
    failed_evaluations: int = 0
    evaluation_coverage: float = Field(ge=0.0, le=1.0, default=0.0, description="Proportion of findings evaluated: successfully_evaluated / total_findings")
    vulnerability_accuracy: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Proportion of correctly identified vulnerabilities among evaluated findings")
    remediation_accuracy: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Proportion of remediations judged technically correct among evaluated findings")
    average_remediation_score: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Mean remediation quality score (0.0 - 1.0) among evaluated findings")
    precision: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Precision score among evaluated findings: TP / (TP + FP)")
    recall: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Recall score among evaluated findings: TP / (TP + FN)")
    f1_score: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Harmonic mean of precision and recall")
    correct_vulnerabilities: int = 0
    incorrect_vulnerabilities: int = 0
    correct_remediations: int = 0
    incorrect_remediations: int = 0
    overall_accuracy: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Overall proportion of fully correct evaluations among evaluated findings")
    total_vulnerabilities: int = 0  # Alias for backward compatibility
    evaluated_count: int = 0        # Alias for backward compatibility
    evaluation_type: str = "LLM-based Evaluation (Gemini Reference Judge)"
    disclaimer: str = (
        "Accuracy is calculated only from successfully evaluated findings. "
        "API failures are excluded from accuracy calculations."
    )


class ReportEvaluationResponse(BaseModel):
    """Complete response returned by /evaluate-report or /reports/{id}/evaluate."""
    report_id: Optional[int] = None
    report_name: str
    total_vulnerabilities: int
    total_findings: int = 0
    evaluation_type: str = "LLM-based Evaluation (Gemini Reference Judge)"
    disclaimer: str = (
        "Accuracy is calculated only from successfully evaluated findings. "
        "API failures are excluded from accuracy calculations."
    )
    metrics: EvaluationMetrics
    evaluations: List[VulnerabilityEvaluationItem]
    status: str = "success"
    message: str = "Evaluation completed successfully."


class EvaluationStatusResponse(BaseModel):
    """Status endpoint response for Gemini API availability."""
    configured: bool
    model: str
    provider: str = "Google Gemini GenAI SDK"
    message: str
