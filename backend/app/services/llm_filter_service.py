from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Callable

from app.ci.config import CredHunterConfig
from app.core.env import load_local_env
from app.scanner.models import NormalizedFinding
from app.services.false_positive_filter import assess_false_positive

LLM_LABELS = {
    "true_positive",
    "likely_true_positive",
    "uncertain",
    "likely_false_positive",
    "false_positive",
}

NON_DOWNGRADABLE_TYPES = {"private_key"}


@dataclass(slots=True)
class LLMClassification:
    classification: str
    confidence: float
    reason: str
    recommended_action: str
    model: str
    used: bool
    skipped_reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_metadata(self) -> dict:
        return {
            "classification": self.classification,
            "confidence": self.confidence,
            "reason": self.reason,
            "recommended_action": self.recommended_action,
            "model": self.model,
            "used": self.used,
            "skipped_reason": self.skipped_reason,
            "metadata": self.metadata,
        }


class LLMFilterService:
    def __init__(
        self,
        config: CredHunterConfig,
        classifier: Callable[[dict[str, Any], CredHunterConfig], dict[str, Any]] | None = None,
    ) -> None:
        self.config = config
        self.classifier = classifier or _openai_classifier

    def classify_findings(
        self,
        findings: list[NormalizedFinding],
        config: CredHunterConfig | None = None,
    ) -> dict[str, LLMClassification]:
        active_config = config or self.config
        assessments: dict[str, LLMClassification] = {}

        for finding in findings:
            assessment = self.classify_finding(finding, active_config)
            if assessment:
                assessments[finding.finding_id] = assessment

        return assessments

    def classify_finding(
        self,
        finding: NormalizedFinding,
        config: CredHunterConfig | None = None,
    ) -> LLMClassification | None:
        active_config = config or self.config
        skip_reason = _skip_reason(finding, active_config)
        if skip_reason:
            return LLMClassification(
                classification="uncertain",
                confidence=0.0,
                reason="LLM classification was skipped.",
                recommended_action="keep_rule_decision",
                model=active_config.llm.model,
                used=False,
                skipped_reason=skip_reason,
            )

        prompt_payload = build_llm_payload(finding, active_config)
        try:
            result = self.classifier(prompt_payload, active_config)
            return _validated_classification(result, active_config.llm.model)
        except Exception as exc:
            return LLMClassification(
                classification="uncertain",
                confidence=0.0,
                reason="LLM classification failed; falling back to deterministic decision.",
                recommended_action="keep_rule_decision",
                model=active_config.llm.model,
                used=False,
                skipped_reason=str(exc),
            )


def build_llm_payload(finding: NormalizedFinding, config: CredHunterConfig) -> dict[str, Any]:
    rule_assessment = assess_false_positive(finding, config)
    return {
        "secret_type": finding.secret_type,
        "redacted_secret": finding.redacted_secret,
        "file_path": finding.file_path,
        "line_number": finding.line_number,
        "detector": finding.detector,
        "rule_id": finding.rule_id,
        "description": finding.description,
        "confidence": finding.confidence,
        "entropy": finding.entropy,
        "context_before": finding.context_before,
        "context_after": finding.context_after,
        "source": finding.source,
        "rule_based_filter": rule_assessment.to_metadata(),
        "safe_metadata": _safe_metadata(finding.metadata),
    }


def _skip_reason(finding: NormalizedFinding, config: CredHunterConfig) -> str | None:
    load_local_env()
    if not config.llm.enabled:
        return "LLM filtering is disabled in configuration."
    if finding.secret_type in NON_DOWNGRADABLE_TYPES:
        return "Finding type is not eligible for LLM downgrade."
    if not os.getenv("OPENAI_API_KEY"):
        return "OPENAI_API_KEY is not set."

    rule_assessment = assess_false_positive(finding, config)
    if rule_assessment.ignored:
        return "Deterministic rule already classified finding as an obvious false positive."
    return None


def _openai_classifier(payload: dict[str, Any], config: CredHunterConfig) -> dict[str, Any]:
    from openai import OpenAI

    load_local_env()
    model = os.getenv("CREDHUNTER_OPENAI_MODEL", config.llm.model)
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    response = client.responses.create(
        model=model,
        instructions=_instructions(),
        input=json.dumps(payload, sort_keys=True),
        max_output_tokens=350,
        store=False,
    )
    return json.loads(response.output_text)


def _instructions() -> str:
    return (
        "You classify redacted Git secret-scanner findings for false-positive filtering. "
        "Never require or infer the raw secret. Return only valid JSON with keys: "
        "classification, confidence, reason, recommended_action. "
        "classification must be one of true_positive, likely_true_positive, uncertain, "
        "likely_false_positive, false_positive. recommended_action must be one of "
        "block, warn, ignore, manual_review, keep_rule_decision. "
        "Be conservative: do not classify provider tokens in source/config files as false positives "
        "unless context is clearly documentation, placeholder, test fixture, or local-only."
    )


def _validated_classification(result: dict[str, Any], model: str) -> LLMClassification:
    classification = str(result.get("classification", "uncertain")).lower()
    if classification not in LLM_LABELS:
        classification = "uncertain"

    confidence = _clamp_float(result.get("confidence", 0.0))
    recommended_action = str(result.get("recommended_action", "keep_rule_decision")).lower()
    if recommended_action not in {"block", "warn", "ignore", "manual_review", "keep_rule_decision"}:
        recommended_action = "keep_rule_decision"

    return LLMClassification(
        classification=classification,
        confidence=confidence,
        reason=str(result.get("reason", "No reason supplied."))[:500],
        recommended_action=recommended_action,
        model=model,
        used=True,
    )


def _safe_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    blocked = {"secret", "raw_secret", "match", "matched_text"}
    return {key: value for key, value in metadata.items() if key.lower() not in blocked}


def _clamp_float(value: Any) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(1.0, parsed))
