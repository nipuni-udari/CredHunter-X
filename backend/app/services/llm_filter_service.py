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
        self.classifier = classifier or classifier_for_workflow(config.llm.workflow)

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


def classifier_for_workflow(
    workflow: str,
) -> Callable[[dict[str, Any], CredHunterConfig], dict[str, Any]]:
    """Return the OpenAI classifier callable for the configured LLM workflow.

    Used for the RQ2 ablation: a single-prompt classifier versus a multi-step
    "agentic" classifier (classify, then justify/verify).
    """

    if (workflow or "single").lower() == "agentic":
        return _openai_agentic_classifier
    return _openai_classifier


def _openai_classifier(payload: dict[str, Any], config: CredHunterConfig) -> dict[str, Any]:
    """Single-prompt workflow: one call returns classification + justification."""

    result = _openai_json_call(
        config=config,
        instructions=_classify_and_justify_instructions(),
        payload=payload,
        max_output_tokens=350,
    )
    result.setdefault("metadata", {})["workflow"] = "single"
    return result


def _openai_agentic_classifier(payload: dict[str, Any], config: CredHunterConfig) -> dict[str, Any]:
    """Multi-step workflow: step 1 classifies, step 2 justifies and self-verifies.

    Step 2 may revise the step-1 label after re-reading the evidence, mirroring a
    simple "classify then critique" agent loop. Both step results are recorded in
    metadata so the RQ2 ablation can compare workflows and inspect label revision.
    """

    step1 = _openai_json_call(
        config=config,
        instructions=_classify_only_instructions(),
        payload=payload,
        max_output_tokens=120,
    )
    initial_label = str(step1.get("classification", "uncertain")).lower()
    initial_confidence = step1.get("confidence", 0.0)

    step2_payload = {
        "finding": payload,
        "preliminary_classification": initial_label,
        "preliminary_confidence": initial_confidence,
    }
    step2 = _openai_json_call(
        config=config,
        instructions=_justify_and_verify_instructions(),
        payload=step2_payload,
        max_output_tokens=350,
    )

    result = dict(step2)
    result.setdefault("classification", initial_label)
    result.setdefault("confidence", initial_confidence)
    metadata = result.setdefault("metadata", {})
    metadata["workflow"] = "agentic"
    metadata["preliminary_classification"] = initial_label
    metadata["preliminary_confidence"] = initial_confidence
    metadata["label_revised"] = str(result.get("classification", "")).lower() != initial_label
    return result


def _openai_json_call(
    config: CredHunterConfig,
    instructions: str,
    payload: dict[str, Any],
    max_output_tokens: int,
) -> dict[str, Any]:
    from openai import OpenAI

    load_local_env()
    model = os.getenv("CREDHUNTER_OPENAI_MODEL", config.llm.model)
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    response = client.responses.create(
        model=model,
        instructions=instructions,
        input=json.dumps(payload, sort_keys=True),
        max_output_tokens=max_output_tokens,
        store=False,
    )
    return json.loads(response.output_text)


_LABEL_RULES = (
    "classification must be one of true_positive, likely_true_positive, uncertain, "
    "likely_false_positive, false_positive. "
)
_ACTION_RULES = (
    "recommended_action must be one of block, warn, ignore, manual_review, keep_rule_decision. "
)
_CONSERVATIVE_RULE = (
    "Be conservative: do not classify provider tokens in source/config files as false positives "
    "unless context is clearly documentation, placeholder, test fixture, or local-only."
)


def _classify_and_justify_instructions() -> str:
    return (
        "You classify redacted Git secret-scanner findings for false-positive filtering. "
        "Never require or infer the raw secret. Return only valid JSON with keys: "
        "classification, confidence, reason, recommended_action. "
        + _LABEL_RULES
        + _ACTION_RULES
        + _CONSERVATIVE_RULE
    )


def _classify_only_instructions() -> str:
    return (
        "You are step 1 of a two-step secret-finding triage. Classify the redacted finding only. "
        "Never require or infer the raw secret. Return only valid JSON with keys: "
        "classification, confidence. "
        + _LABEL_RULES
        + _CONSERVATIVE_RULE
    )


def _justify_and_verify_instructions() -> str:
    return (
        "You are step 2 of a two-step secret-finding triage. You receive the finding and a "
        "preliminary classification. Re-check the evidence, correct the classification if it is "
        "wrong, then justify it. Never require or infer the raw secret. Return only valid JSON with "
        "keys: classification, confidence, reason, recommended_action. "
        + _LABEL_RULES
        + _ACTION_RULES
        + _CONSERVATIVE_RULE
    )


def _validated_classification(result: dict[str, Any], model: str) -> LLMClassification:
    classification = str(result.get("classification", "uncertain")).lower()
    if classification not in LLM_LABELS:
        classification = "uncertain"

    confidence = _clamp_float(result.get("confidence", 0.0))
    recommended_action = str(result.get("recommended_action", "keep_rule_decision")).lower()
    if recommended_action not in {"block", "warn", "ignore", "manual_review", "keep_rule_decision"}:
        recommended_action = "keep_rule_decision"

    metadata = result.get("metadata")
    return LLMClassification(
        classification=classification,
        confidence=confidence,
        reason=str(result.get("reason", "No reason supplied."))[:500],
        recommended_action=recommended_action,
        model=model,
        used=True,
        metadata=metadata if isinstance(metadata, dict) else {},
    )


def _safe_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    blocked = {"secret", "raw_secret", "match", "matched_text", "ground_truth", "ground_truth_raw", "label"}
    return {key: value for key, value in metadata.items() if key.lower() not in blocked}


def _clamp_float(value: Any) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(1.0, parsed))
