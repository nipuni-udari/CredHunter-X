from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePosixPath

from app.ci.config import CredHunterConfig
from app.scanner.models import NormalizedFinding
from app.scanner.provider_inference import (
    apply_provider_inference,
    apply_score_floor,
    provider_floor_for_finding,
    risk_floor_metadata,
)
from app.services.false_positive_filter import FalsePositiveAssessment
from app.services.llm_filter_service import LLMClassification
from app.services.validation_service import ValidationResult


@dataclass(slots=True)
class RiskComponent:
    name: str
    value: int
    reason: str

    def to_dict(self) -> dict:
        return {"name": self.name, "value": self.value, "reason": self.reason}


@dataclass(slots=True)
class RiskScore:
    score: int
    risk_level: str
    recommended_action: str
    components: list[RiskComponent] = field(default_factory=list)
    # "rules" -> deterministic composite score; "llm" -> refined by the LLM Ranker.
    source: str = "rules"
    rationale: str | None = None
    risk_floor: dict | None = None

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "risk_level": self.risk_level,
            "recommended_action": self.recommended_action,
            "components": [component.to_dict() for component in self.components],
            "source": self.source,
            "rationale": self.rationale,
            "risk_floor": self.risk_floor,
        }


SECRET_TYPE_WEIGHTS = {
    "private_key": 50,
    "aws_access_key": 40,
    "aws_access_key_id": 40,
    "openai_api_key": 40,
    "stripe_api_key": 40,
    "github_token": 35,
    "google_api_key": 35,
    "slack_token": 30,
    "database_url": 30,
    "oauth_token": 30,
    "bearer_token": 30,
    "jwt": 20,
    "generic_high_entropy_secret": 15,
    "generic_secret": 15,
}

RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def score_finding(
    finding: NormalizedFinding,
    config: CredHunterConfig,
    false_positive_assessment: FalsePositiveAssessment,
    llm_classification: LLMClassification | None = None,
    validation_result: ValidationResult | None = None,
) -> RiskScore:
    apply_provider_inference(finding)
    components = [
        _detector_component(finding),
        _secret_type_component(finding),
        *_file_context_components(finding),
        *_false_positive_components(false_positive_assessment),
        *_llm_components(finding, config, llm_classification),
        *_validation_components(validation_result),
    ]

    raw_score = sum(component.value for component in components)
    score = _clamp(raw_score)

    applied_floor = None
    if not _risk_floor_exempt(finding, false_positive_assessment, llm_classification, config):
        score, applied_floor = apply_score_floor(score, provider_floor_for_finding(finding))
        if applied_floor:
            components.append(
                RiskComponent(
                    "provider_risk_floor",
                    applied_floor.minimum_score - _clamp(raw_score),
                    f"Provider-specific floor applied: {applied_floor.provider}:{applied_floor.minimum_score}.",
                )
            )
    if _needs_conservative_medium_floor(finding, false_positive_assessment, llm_classification, config):
        score = max(score, 35)

    risk_level = _risk_level_from_score(score)
    return RiskScore(
        score=score,
        risk_level=risk_level,
        recommended_action=_recommended_action(risk_level),
        components=components,
        risk_floor=risk_floor_metadata(applied_floor),
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


def risk_value(risk_level: str) -> int:
    return RISK_ORDER.get(risk_level.lower(), RISK_ORDER["high"])


def _detector_component(finding: NormalizedFinding) -> RiskComponent:
    value = int(round(max(0.0, min(1.0, finding.confidence)) * 30))
    return RiskComponent("detector_score", value, f"Detector confidence is {finding.confidence:.2f}.")


def _secret_type_component(finding: NormalizedFinding) -> RiskComponent:
    value = SECRET_TYPE_WEIGHTS.get(finding.secret_type, 15)
    return RiskComponent("secret_type_weight", value, f"Secret type is {finding.secret_type}.")


def _file_context_components(finding: NormalizedFinding) -> list[RiskComponent]:
    normalized = finding.file_path.replace("\\", "/").lower()
    path = PurePosixPath(normalized)
    parts = set(path.parts)
    components: list[RiskComponent] = []

    if path.name.startswith(".env"):
        components.append(RiskComponent("file_context_weight", 20, "Secret appears in an environment file."))
    if any(part in parts for part in {"prod", "production", "deploy", "deployment", "secrets"}):
        components.append(RiskComponent("file_context_weight", 20, "Secret appears in production/deployment context."))
    if ".github" in parts or "workflow" in normalized or "ci" in parts:
        components.append(RiskComponent("git_exposure_weight", 10, "Secret appears in CI/CD context."))
    if any(part in parts for part in {"docs", "doc", "examples", "example", "tests", "fixtures", "mock", "mocks"}):
        components.append(RiskComponent("false_positive_weight", -25, "Finding appears in docs/examples/tests context."))
    if path.suffix in {".md", ".rst", ".adoc"}:
        components.append(RiskComponent("false_positive_weight", -20, "Finding appears in documentation file type."))

    return components


def _false_positive_components(assessment: FalsePositiveAssessment) -> list[RiskComponent]:
    if assessment.classification == "false_positive":
        return [RiskComponent("false_positive_weight", -60, "Rule-based filter classified finding as false positive.")]
    if assessment.classification == "likely_false_positive":
        return [RiskComponent("false_positive_weight", -45, "Rule-based filter classified finding as likely false positive.")]
    if assessment.classification == "uncertain":
        return [RiskComponent("false_positive_weight", -10, "Rule-based filter marked finding as uncertain.")]
    return []


def _llm_components(
    finding: NormalizedFinding,
    config: CredHunterConfig,
    classification: LLMClassification | None,
) -> list[RiskComponent]:
    if not classification or not classification.used:
        return []
    if classification.confidence < config.llm.min_confidence:
        return [RiskComponent("llm_weight", 0, "LLM confidence is below the configured minimum.")]
    if finding.secret_type == "private_key" and classification.classification in {"likely_false_positive", "false_positive"}:
        return [RiskComponent("llm_weight", 0, "LLM cannot downgrade private key findings.")]

    if classification.classification == "true_positive":
        return [RiskComponent("llm_weight", 40, "LLM classified finding as true positive.")]
    if classification.classification == "likely_true_positive":
        return [RiskComponent("llm_weight", 30, "LLM classified finding as likely true positive.")]
    if classification.classification == "likely_false_positive":
        return [RiskComponent("llm_weight", -35, "LLM classified finding as likely false positive.")]
    if classification.classification == "false_positive":
        return [RiskComponent("llm_weight", -50, "LLM classified finding as false positive.")]
    return []


def _validation_components(validation_result: ValidationResult | None) -> list[RiskComponent]:
    if not validation_result or not validation_result.checked:
        return []
    if validation_result.active is True:
        return [RiskComponent("validation_weight", 50, "Validation confirmed the credential is active.")]
    if validation_result.status in {"invalid", "expired", "local_only"}:
        return [RiskComponent("validation_weight", -45, f"Validation returned {validation_result.status}.")]
    if validation_result.status == "unverified_external":
        return [RiskComponent("validation_weight", 10, "External-looking credential could not be safely verified.")]
    return [RiskComponent("validation_weight", 0, f"Validation returned {validation_result.status}.")]


def _needs_conservative_medium_floor(
    finding: NormalizedFinding,
    assessment: FalsePositiveAssessment,
    llm_classification: LLMClassification | None,
    config: CredHunterConfig,
) -> bool:
    if assessment.classification != "uncertain":
        return False
    if finding.secret_type not in {"aws_access_key", "aws_access_key_id", "github_token", "database_url", "oauth_token", "bearer_token"}:
        return False
    if (
        llm_classification
        and llm_classification.used
        and llm_classification.confidence >= config.llm.min_confidence
        and llm_classification.classification in {"likely_false_positive", "false_positive"}
    ):
        return False
    return True


def risk_level_from_score(score: int) -> str:
    """Map a 0-100 risk score to a risk level (shared by the rules and LLM rankers)."""

    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def recommended_action_for_level(risk_level: str) -> str:
    """Map a risk level to its default CI action (shared by both rankers)."""

    return {
        "critical": "fail",
        "high": "manual_review",
        "medium": "warn",
        "low": "pass",
    }[risk_level]


# Backwards-compatible internal aliases.
_risk_level_from_score = risk_level_from_score
_recommended_action = recommended_action_for_level


def _clamp(score: int) -> int:
    return max(0, min(100, score))
