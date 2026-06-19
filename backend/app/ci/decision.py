from __future__ import annotations

from dataclasses import dataclass

from app.reporting.remediation import remediation_steps
from app.scanner.models import NormalizedFinding
from app.services.false_positive_filter import FalsePositiveAssessment, assess_false_positive
from app.services.llm_filter_service import LLMClassification
from app.services.risk_scoring_service import RiskScore, risk_value, score_finding
from app.services.validation_service import ValidationResult

from .config import CredHunterConfig


@dataclass(slots=True)
class FindingDecision:
    finding: NormalizedFinding
    risk_level: str
    action: str
    reason: str
    false_positive_assessment: FalsePositiveAssessment | None = None
    llm_classification: LLMClassification | None = None
    risk_score: RiskScore | None = None
    validation_result: ValidationResult | None = None

    def to_dict(self) -> dict:
        payload = self.finding.to_dict()
        payload["risk_level"] = self.risk_level
        payload["action"] = self.action
        payload["decision_reason"] = self.reason
        if self.action != "ignore":
            payload["remediation"] = remediation_steps(self.finding.secret_type)
        if self.false_positive_assessment:
            payload["false_positive_filter"] = self.false_positive_assessment.to_metadata()
        if self.llm_classification:
            payload["llm_filter"] = self.llm_classification.to_metadata()
        if self.validation_result:
            payload["validation"] = self.validation_result.to_dict()
        if self.risk_score:
            payload["risk_score"] = self.risk_score.to_dict()
        return payload


@dataclass(slots=True)
class CIDecision:
    action: str
    exit_code: int
    finding_count: int
    blocking_count: int
    warning_count: int
    manual_review_count: int
    ignored_count: int
    findings: list[FindingDecision]

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "exit_code": self.exit_code,
            "finding_count": self.finding_count,
            "blocking_count": self.blocking_count,
            "warning_count": self.warning_count,
            "manual_review_count": self.manual_review_count,
            "ignored_count": self.ignored_count,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def evaluate_findings(
    findings: list[NormalizedFinding],
    config: CredHunterConfig,
    llm_classifications: dict[str, LLMClassification] | None = None,
    validation_results: dict[str, ValidationResult] | None = None,
) -> CIDecision:
    llm_classifications = llm_classifications or {}
    validation_results = validation_results or {}
    decisions = [
        _evaluate_finding(
            finding,
            config,
            llm_classifications.get(finding.finding_id),
            validation_results.get(finding.finding_id),
        )
        for finding in findings
    ]
    blocking = [item for item in decisions if item.action == "fail"]
    warnings = [item for item in decisions if item.action == "warn"]
    manual_reviews = [item for item in decisions if item.action == "manual_review"]
    ignored = [item for item in decisions if item.action == "ignore"]

    if blocking:
        action = "fail"
        exit_code = 1
    elif manual_reviews:
        action = "manual_review"
        exit_code = 0
    elif warnings:
        action = "warn"
        exit_code = 0
    else:
        action = "pass"
        exit_code = 0

    return CIDecision(
        action=action,
        exit_code=exit_code,
        finding_count=len(decisions),
        blocking_count=len(blocking),
        warning_count=len(warnings),
        manual_review_count=len(manual_reviews),
        ignored_count=len(ignored),
        findings=decisions,
    )


def _evaluate_finding(
    finding: NormalizedFinding,
    config: CredHunterConfig,
    llm_classification: LLMClassification | None = None,
    validation_result: ValidationResult | None = None,
) -> FindingDecision:
    assessment = assess_false_positive(finding, config)
    risk_score = score_finding(finding, config, assessment, llm_classification, validation_result)
    if assessment.ignored:
        return FindingDecision(
            finding,
            risk_score.risk_level,
            "ignore",
            " ".join(assessment.reasons),
            assessment,
            llm_classification,
            risk_score,
            validation_result,
        )

    risk_level = risk_score.risk_level
    threshold = config.scan.fail_on

    if risk_value(risk_level) >= risk_value(threshold):
        reason = f"Risk score {risk_score.score} is {risk_level}, at or above fail_on={threshold}."
        if llm_classification and llm_classification.used:
            reason = f"{reason} LLM classification: {llm_classification.classification}."
        return FindingDecision(
            finding,
            risk_level,
            "fail",
            reason,
            assessment,
            llm_classification,
            risk_score,
            validation_result,
        )

    if risk_level == "high":
        return FindingDecision(
            finding,
            risk_level,
            "manual_review",
            f"Risk score {risk_score.score} requires manual review but is below blocking threshold.",
            assessment,
            llm_classification,
            risk_score,
            validation_result,
        )

    if risk_level == "medium":
        return FindingDecision(
            finding,
            risk_level,
            "warn",
            f"Risk score {risk_score.score} is medium and should be reviewed.",
            assessment,
            llm_classification,
            risk_score,
            validation_result,
        )

    action = "ignore" if _llm_can_ignore(finding, config, llm_classification) else risk_score.recommended_action
    reason = f"Risk score {risk_score.score} is low for the current threshold."
    if action == "ignore":
        reason = "LLM classified the finding as a likely false positive with sufficient confidence."
    return FindingDecision(finding, risk_level, action, reason, assessment, llm_classification, risk_score, validation_result)


def _llm_can_ignore(
    finding: NormalizedFinding,
    config: CredHunterConfig,
    llm_classification: LLMClassification | None,
) -> bool:
    if not llm_classification or not llm_classification.used:
        return False
    if finding.secret_type == "private_key":
        return False
    if llm_classification.confidence < config.llm.min_confidence:
        return False
    return llm_classification.classification in {"likely_false_positive", "false_positive"}
