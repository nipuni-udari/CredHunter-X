"""LLM Explainer stage.

The third stage of the LLM pipeline (classify -> rank -> explain -> remediate).
It turns the structured classification and risk score into a short, developer
facing explanation of *why* the finding was flagged and how concerned to be.

Unlike the classifier's ``reason`` field (which justifies the label for the
filtering logic), this explanation is written for the engineer reading the PR
comment: plain language, grounded in the finding's type, location and signals,
and never echoing the raw secret.

The stage is optional and degrades gracefully: when disabled, unavailable, or on
any error it returns an unused result and the report falls back to the existing
rule/classification reason.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from app.ci.config import CredHunterConfig
from app.scanner.models import NormalizedFinding
from app.scanner.provider_inference import apply_provider_inference
from app.services.false_positive_filter import assess_false_positive
from app.services.llm_client import llm_ready, openai_json_call
from app.services.llm_filter_service import LLMClassification, build_llm_payload
from app.services.llm_ranker_service import LLMRanking

MAX_EXPLANATION_LENGTH = 800

Explainer = Callable[[dict[str, Any], CredHunterConfig], dict[str, Any]]

EXPLAINER_SCHEMA = {
    "type": "object",
    "properties": {
        "explanation": {"type": "string"},
    },
    "required": ["explanation"],
    "additionalProperties": False,
}


@dataclass(slots=True)
class LLMExplanation:
    explanation: str
    model: str
    used: bool
    skipped_reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_metadata(self) -> dict:
        return {
            "explanation": self.explanation,
            "model": self.model,
            "used": self.used,
            "skipped_reason": self.skipped_reason,
            "metadata": self.metadata,
        }


class LLMExplainerService:
    def __init__(self, config: CredHunterConfig, explainer: Explainer | None = None) -> None:
        self.config = config
        self.explainer = explainer or _openai_explainer

    def explain_findings(
        self,
        findings: list[NormalizedFinding],
        classifications: dict[str, LLMClassification] | None = None,
        rankings: dict[str, LLMRanking] | None = None,
        config: CredHunterConfig | None = None,
    ) -> dict[str, LLMExplanation]:
        active_config = config or self.config
        classifications = classifications or {}
        rankings = rankings or {}
        explanations: dict[str, LLMExplanation] = {}
        for finding in findings:
            explanation = self.explain_finding(
                finding,
                classifications.get(finding.finding_id),
                rankings.get(finding.finding_id),
                active_config,
            )
            if explanation:
                explanations[finding.finding_id] = explanation
        return explanations

    def explain_finding(
        self,
        finding: NormalizedFinding,
        classification: LLMClassification | None = None,
        ranking: LLMRanking | None = None,
        config: CredHunterConfig | None = None,
    ) -> LLMExplanation | None:
        active_config = config or self.config
        apply_provider_inference(finding)

        skip_reason = _skip_reason(finding, active_config)
        if skip_reason:
            return _unused(active_config.llm.model, skip_reason)

        payload = _build_explain_payload(finding, active_config, classification, ranking)
        try:
            result = self.explainer(payload, active_config)
            return _validated_explanation(result, active_config.llm.model)
        except Exception as exc:  # noqa: BLE001 - any failure falls back to rule reason.
            return _unused(active_config.llm.model, str(exc))


def _skip_reason(finding: NormalizedFinding, config: CredHunterConfig) -> str | None:
    if assess_false_positive(finding, config).ignored:
        return "Deterministic rule already classified finding as an obvious false positive."
    if not config.llm.explain:
        return "LLM explanation is disabled in configuration."
    return llm_ready(config)


def _unused(model: str, skipped_reason: str) -> LLMExplanation:
    is_local_skip = "classified finding as an obvious false positive" in skipped_reason
    return LLMExplanation(
        explanation="",
        model=model,
        used=False,
        skipped_reason=skipped_reason,
        metadata={"fallback": not is_local_skip, "error": skipped_reason} if not is_local_skip else {"fallback": False, "skipped": True},
    )


def _build_explain_payload(
    finding: NormalizedFinding,
    config: CredHunterConfig,
    classification: LLMClassification | None,
    ranking: LLMRanking | None,
) -> dict[str, Any]:
    payload = build_llm_payload(finding, config)
    if classification and classification.used:
        payload["llm_classification"] = {
            "classification": classification.classification,
            "confidence": classification.confidence,
            "reason": classification.reason,
        }
    if ranking:
        payload["risk"] = {"score": ranking.score, "risk_level": ranking.risk_level}
    return payload


def _validated_explanation(result: dict[str, Any], model: str) -> LLMExplanation:
    explanation = str(result.get("explanation", "")).strip()[:MAX_EXPLANATION_LENGTH]
    if not explanation:
        return _unused(model, "LLM returned an empty explanation.")

    metadata = result.get("metadata")
    return LLMExplanation(
        explanation=explanation,
        model=model,
        used=True,
        metadata=metadata if isinstance(metadata, dict) else {},
    )


def _openai_explainer(payload: dict[str, Any], config: CredHunterConfig) -> dict[str, Any]:
    return openai_json_call(
        config=config,
        instructions=_explain_instructions(),
        payload=payload,
        max_output_tokens=300,
        schema_name="credhunter_explainer",
        schema=EXPLAINER_SCHEMA,
    )


def _explain_instructions() -> str:
    return (
        "You are the explanation stage of a secret-scanner triage pipeline. You receive a redacted "
        "finding, its classification, and its risk score. Write a concise developer-facing "
        "explanation (one to three sentences) of why this was flagged and how serious it is, "
        "grounded in the secret type, file location, and any signals provided. Use plain language a "
        "developer can act on. Never require, infer, or repeat the raw secret. Return a structured "
        "result with key: explanation (string)."
    )
