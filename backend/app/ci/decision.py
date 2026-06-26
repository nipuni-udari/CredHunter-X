from __future__ import annotations

from dataclasses import dataclass

from app.reporting.remediation import remediation_steps
from app.scanner.models import NormalizedFinding
from app.scanner.provider_inference import (
    apply_provider_inference,
    apply_score_floor,
    provider_floor_for_finding,
    risk_floor_metadata,
)
from app.services.false_positive_filter import FalsePositiveAssessment, assess_false_positive
from app.services.llm_explainer_service import LLMExplanation
from app.services.llm_filter_service import LLMClassification
from app.services.llm_ranker_service import LLMRanking
from app.services.llm_remediation_service import LLMRemediation
from app.services.risk_scoring_service import (
    RiskComponent,
    RiskScore,
    recommended_action_for_level,
    risk_level_from_score,
    risk_value,
    score_finding,
)
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
    llm_ranking: LLMRanking | None = None
    llm_explanation: LLMExplanation | None = None
    llm_remediation: LLMRemediation | None = None

    def remediation(self) -> list[str]:
        """Remediation steps for this finding: LLM-generated when available, else template."""

        if self.llm_remediation and self.llm_remediation.used:
            return self.llm_remediation.steps
        return remediation_steps(self.finding.secret_type)

    def explanation(self) -> str:
        """Developer-facing explanation: LLM-generated when available, else the decision reason."""

        if self.llm_explanation and self.llm_explanation.used:
            return self.llm_explanation.explanation
        return self.reason

    def to_dict(self) -> dict:
        payload = self.finding.to_dict()
        payload["risk_level"] = self.risk_level
        payload["action"] = self.action
        payload["decision_reason"] = self.reason
        if self.action != "ignore":
            payload["remediation"] = self.remediation()
        if self.false_positive_assessment:
            payload["false_positive_filter"] = self.false_positive_assessment.to_metadata()
        if self.llm_classification:
            payload["llm_filter"] = self.llm_classification.to_metadata()
        if self.validation_result:
            payload["validation"] = self.validation_result.to_dict()
        if self.risk_score:
            payload["risk_score"] = self.risk_score.to_dict()
        if self.llm_ranking:
            payload["llm_ranking"] = self.llm_ranking.to_metadata()
        if self.llm_explanation:
            payload["llm_explanation"] = self.llm_explanation.to_metadata()
        if self.llm_remediation:
            payload["llm_remediation"] = self.llm_remediation.to_metadata()
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
    llm_status: dict | None = None

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "exit_code": self.exit_code,
            "finding_count": self.finding_count,
            "blocking_count": self.blocking_count,
            "warning_count": self.warning_count,
            "manual_review_count": self.manual_review_count,
            "ignored_count": self.ignored_count,
            "llm_status": self.llm_status,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def evaluate_findings(
    findings: list[NormalizedFinding],
    config: CredHunterConfig,
    llm_classifications: dict[str, LLMClassification] | None = None,
    validation_results: dict[str, ValidationResult] | None = None,
    llm_rankings: dict[str, LLMRanking] | None = None,
    llm_explanations: dict[str, LLMExplanation] | None = None,
    llm_remediations: dict[str, LLMRemediation] | None = None,
) -> CIDecision:
    llm_classifications = llm_classifications or {}
    validation_results = validation_results or {}
    llm_rankings = llm_rankings or {}
    llm_explanations = llm_explanations or {}
    llm_remediations = llm_remediations or {}
    decisions = [
        _evaluate_finding(
            finding,
            config,
            llm_classifications.get(finding.finding_id),
            validation_results.get(finding.finding_id),
            llm_rankings.get(finding.finding_id),
            llm_explanations.get(finding.finding_id),
            llm_remediations.get(finding.finding_id),
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
        llm_status=_llm_status(
            config, llm_classifications, llm_rankings, llm_explanations, llm_remediations
        ),
    )


def _llm_status(
    config: CredHunterConfig,
    classifications: dict[str, LLMClassification],
    rankings: dict[str, LLMRanking],
    explanations: dict[str, LLMExplanation],
    remediations: dict[str, LLMRemediation],
) -> dict:
    """Summarise whether each LLM stage actually ran or fell back to deterministic.

    Surfaced in the report/PR comment so a developer can see at a glance whether a
    decision came from the LLM (the main path) or the deterministic fallback (e.g.
    no OPENAI_API_KEY, or an API error)."""

    def stage_state(stage_enabled: bool, results: dict) -> str:
        if not stage_enabled:
            return "off"
        return "active" if any(getattr(r, "used", False) for r in results.values()) else "fallback"

    stages = {
        "classify": stage_state(config.llm.enabled, classifications),
        "rank": stage_state(config.llm.enabled and config.llm.rank, rankings),
        "explain": stage_state(config.llm.enabled and config.llm.explain, explanations),
        "remediate": stage_state(config.llm.enabled and config.llm.remediate, remediations),
    }
    active = any(state == "active" for state in stages.values())

    if not config.llm.enabled:
        mode, reason = "deterministic", "LLM disabled in configuration."
    elif active:
        mode, reason = "llm", None
    else:
        mode = "fallback"
        reason = _first_skip_reason(classifications) or "LLM stages did not run."

    return {
        "mode": mode,
        "active": active,
        "enabled": config.llm.enabled,
        "model": config.llm.model,
        "stages": stages,
        "reason": reason,
    }


def _first_skip_reason(classifications: dict[str, LLMClassification]) -> str | None:
    fallback_reason = None
    for classification in classifications.values():
        if not classification.used and classification.skipped_reason:
            if fallback_reason is None:
                fallback_reason = classification.skipped_reason
            if "classified finding as an obvious false positive" not in classification.skipped_reason:
                return classification.skipped_reason
    return fallback_reason


def _evaluate_finding(
    finding: NormalizedFinding,
    config: CredHunterConfig,
    llm_classification: LLMClassification | None = None,
    validation_result: ValidationResult | None = None,
    llm_ranking: LLMRanking | None = None,
    llm_explanation: LLMExplanation | None = None,
    llm_remediation: LLMRemediation | None = None,
) -> FindingDecision:
    apply_provider_inference(finding)
    assessment = assess_false_positive(finding, config)
    risk_score = score_finding(finding, config, assessment, llm_classification, validation_result)
    if llm_ranking and llm_ranking.used:
        risk_score = _apply_llm_ranking(
            finding,
            config,
            assessment,
            llm_classification,
            risk_score,
            llm_ranking,
        )

    def decide(risk_level: str, action: str, reason: str) -> FindingDecision:
        return FindingDecision(
            finding,
            risk_level,
            action,
            reason,
            assessment,
            llm_classification,
            risk_score,
            validation_result,
            llm_ranking,
            llm_explanation,
            llm_remediation,
        )

    if assessment.ignored:
        return decide(risk_score.risk_level, "ignore", " ".join(assessment.reasons))

    risk_level = risk_score.risk_level
    threshold = config.scan.fail_on

    if risk_value(risk_level) >= risk_value(threshold):
        reason = f"Risk score {risk_score.score} is {risk_level}, at or above fail_on={threshold}."
        if llm_classification and llm_classification.used:
            reason = f"{reason} LLM classification: {llm_classification.classification}."
        return decide(risk_level, "fail", reason)

    if risk_level == "high":
        return decide(
            risk_level,
            "manual_review",
            f"Risk score {risk_score.score} requires manual review but is below blocking threshold.",
        )

    if risk_level == "medium":
        return decide(
            risk_level,
            "warn",
            f"Risk score {risk_score.score} is medium and should be reviewed.",
        )

    action = "ignore" if _llm_can_ignore(finding, config, llm_classification) else risk_score.recommended_action
    reason = f"Risk score {risk_score.score} is low for the current threshold."
    if action == "ignore":
        reason = "LLM classified the finding as a likely false positive with sufficient confidence."
    return decide(risk_level, action, reason)


def _apply_llm_ranking(
    finding: NormalizedFinding,
    config: CredHunterConfig,
    assessment: FalsePositiveAssessment,
    llm_classification: LLMClassification | None,
    base_score: RiskScore,
    ranking: LLMRanking,
) -> RiskScore:
    """Replace the deterministic score with the LLM Ranker's, keeping the rule
    components for transparency and recording the adjustment."""

    components = list(base_score.components)
    final_score = ranking.score
    final_floor = None
    if not _risk_floor_exempt(finding, assessment, llm_classification, config):
        final_score, final_floor = apply_score_floor(final_score, provider_floor_for_finding(finding))
    components.append(
        RiskComponent(
            "llm_ranking",
            final_score - base_score.score,
            f"LLM Ranker set score to {final_score}: {ranking.rationale}",
        )
    )
    if final_floor:
        components.append(
            RiskComponent(
                "provider_risk_floor",
                final_floor.minimum_score - ranking.score,
                f"Provider-specific floor applied after LLM ranking: {final_floor.provider}:{final_floor.minimum_score}.",
            )
        )
    risk_level = ranking.risk_level
    recommended_action = ranking.recommended_action
    if final_score != ranking.score:
        risk_level = risk_level_from_score(final_score)
        recommended_action = recommended_action_for_level(risk_level)
    return RiskScore(
        score=final_score,
        risk_level=risk_level,
        recommended_action=recommended_action,
        components=components,
        source="llm",
        rationale=ranking.rationale,
        risk_floor=risk_floor_metadata(final_floor) or base_score.risk_floor,
    )


def _risk_floor_exempt(
    finding: NormalizedFinding,
    assessment: FalsePositiveAssessment,
    llm_classification: LLMClassification | None,
    config: CredHunterConfig,
) -> bool:
    if assessment.ignored:
        return True
    if finding.secret_type == "private_key":
        return False
    if (
        llm_classification
        and llm_classification.used
        and llm_classification.confidence >= config.llm.min_confidence
        and llm_classification.classification in {"likely_false_positive", "false_positive"}
    ):
        return True
    return False


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
