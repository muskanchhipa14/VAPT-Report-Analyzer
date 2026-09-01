from typing import List
from app.schemas.evaluation import VulnerabilityEvaluationItem, EvaluationMetrics


def calculate_metrics(
    evaluations: List[VulnerabilityEvaluationItem],
    total_report_vulnerabilities: int
) -> EvaluationMetrics:
    """
    Calculates independent evaluation metrics comparing the system's output
    against Gemini's evaluation judgment.

    Distinguishes:
    - total_findings: Total number of detected findings in the report
    - successfully_evaluated: Findings that received a valid Gemini evaluation
    - failed_evaluations: Findings where evaluation failed (e.g. 429 quota or network)
    - evaluation_coverage: successfully_evaluated / total_findings
    - Vulnerability identification accuracy (among evaluated findings)
    - Remediation accuracy (among evaluated findings)
    - Average remediation score (0.0 to 1.0 among evaluated findings)
    - Precision, Recall, and F1 Score (among evaluated findings)
    - Overall accuracy (among evaluated findings)
    """
    total_findings = total_report_vulnerabilities if total_report_vulnerabilities > 0 else len(evaluations)
    
    # Filter successfully evaluated items vs failed/pending items
    successfully_evaluated_items = [
        item for item in evaluations
        if item.evaluation_status == "success" and item.gemini_evaluation is not None
    ]
    
    failed_items = [
        item for item in evaluations
        if item.evaluation_status != "success" or item.gemini_evaluation is None
    ]
    
    successfully_evaluated = len(successfully_evaluated_items)
    failed_evaluations = len(failed_items)
    
    coverage = round(successfully_evaluated / total_findings, 4) if total_findings > 0 else 0.0
    
    if successfully_evaluated == 0:
        return EvaluationMetrics(
            total_findings=total_findings,
            successfully_evaluated=0,
            failed_evaluations=failed_evaluations,
            evaluation_coverage=coverage,
            vulnerability_accuracy=None,
            remediation_accuracy=None,
            average_remediation_score=None,
            precision=None,
            recall=None,
            f1_score=None,
            correct_vulnerabilities=0,
            incorrect_vulnerabilities=0,
            correct_remediations=0,
            incorrect_remediations=0,
            overall_accuracy=None,
            total_vulnerabilities=total_findings,
            evaluated_count=0,
            evaluation_type="LLM-based Evaluation (Gemini Reference Judge)",
            disclaimer=(
                "No successful Gemini evaluations were available for this report. "
                "Accuracy is calculated only from successfully evaluated findings. "
                "API failures are excluded from accuracy calculations."
            )
        )

    correct_vulns = sum(
        1 for item in successfully_evaluated_items if item.gemini_evaluation.is_vulnerability_correct
    )
    incorrect_vulns = successfully_evaluated - correct_vulns

    correct_remediations = sum(
        1 for item in successfully_evaluated_items if item.gemini_evaluation.remediation_is_correct
    )
    incorrect_remediations = successfully_evaluated - correct_remediations

    total_remediation_score = sum(
        max(0.0, min(1.0, float(item.gemini_evaluation.remediation_score)))
        for item in successfully_evaluated_items
    )
    avg_remediation_score = round(total_remediation_score / successfully_evaluated, 4)

    vuln_accuracy = round(correct_vulns / successfully_evaluated, 4)
    remediation_accuracy = round(correct_remediations / successfully_evaluated, 4)

    overall_correct_count = sum(
        1 for item in successfully_evaluated_items if item.gemini_evaluation.overall_correct
    )
    overall_accuracy = round(overall_correct_count / successfully_evaluated, 4)

    # Precision, Recall, F1 Calculation on evaluated findings:
    # TP = correctly detected vulnerabilities
    # FP = incorrectly detected vulnerabilities (false alarms)
    # FN = false negatives (incorrect detections in reference)
    tp = correct_vulns
    fp = incorrect_vulns
    fn = incorrect_vulns

    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    
    if (precision + recall) > 0:
        f1_score = round(2 * (precision * recall) / (precision + recall), 4)
    else:
        f1_score = 0.0

    return EvaluationMetrics(
        total_findings=total_findings,
        successfully_evaluated=successfully_evaluated,
        failed_evaluations=failed_evaluations,
        evaluation_coverage=coverage,
        vulnerability_accuracy=vuln_accuracy,
        remediation_accuracy=remediation_accuracy,
        average_remediation_score=avg_remediation_score,
        precision=precision,
        recall=recall,
        f1_score=f1_score,
        correct_vulnerabilities=correct_vulns,
        incorrect_vulnerabilities=incorrect_vulns,
        correct_remediations=correct_remediations,
        incorrect_remediations=incorrect_remediations,
        overall_accuracy=overall_accuracy,
        total_vulnerabilities=total_findings,
        evaluated_count=successfully_evaluated,
        evaluation_type="LLM-based Evaluation (Gemini Reference Judge)",
        disclaimer=(
            "Accuracy is calculated only from successfully evaluated findings. "
            "API failures are excluded from accuracy calculations."
        )
    )

