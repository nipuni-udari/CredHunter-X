"""LLM Remediation stage.

The final stage of the LLM pipeline (classify -> rank -> explain -> remediate).
It produces concrete, context-specific remediation steps for a confirmed or
suspected secret, going beyond the static per-type templates in
``app.reporting.remediation`` by taking the file location, secret type and
classification into account.

When disabled, unavailable, or on any error it returns an unused result; callers
fall back to the deterministic ``remediation_steps`` template so a developer
always receives guidance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from app.ci.config import CredHunterConfig
from app.reporting.remediation import remediation_steps
from app.scanner.models import NormalizedFinding
from app.services.llm_client import llm_ready, openai_json_call
from app.services.llm_filter_service import LLMClassification, build_llm_payload
from app.services.llm_ranker_service import LLMRanking

MAX_STEPS = 5
MAX_STEP_LENGTH = 240

Remediator = Callable[[dict[str, Any], CredHunterConfig], dict[str, Any]]


@dataclass(slots=True)
class LLMRemediation:
    steps: list[str]
    model: str
    used: bool
    skipped_reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_metadata(self) -> dict:
        return {
            "steps": self.steps,
            "model": self.model,
            "used": self.used,
            "skipped_reason": self.skipped_reason,
            "metadata": self.metadata,
        }


class LLMRemediationService:
    def __init__(self, config: CredHunterConfig, remediator: Remediator | None = None) -> None:
        self.config = config
        self.remediator = remediator or _openai_remediator

    def remediate_findings(
        self,
        findings: list[NormalizedFinding],
        classifications: dict[str, LLMClassification] | None = None,
        rankings: dict[str, LLMRanking] | None = None,
        config: CredHunterConfig | None = None,
    ) -> dict[str, LLMRemediation]:
        active_config = config or self.config
        classifications = classifications or {}
        rankings = rankings or {}
        results: dict[str, LLMRemediation] = {}
        for finding in findings:
            remediation = self.remediate_finding(
                finding,
                classifications.get(finding.finding_id),
                rankings.get(finding.finding_id),
                active_config,
            )
            if remediation:
                results[finding.finding_id] = remediation
        return results

    def remediate_finding(
        self,
        finding: NormalizedFinding,
        classification: LLMClassification | None = None,
        ranking: LLMRanking | None = None,
        config: CredHunterConfig | None = None,
    ) -> LLMRemediation | None:
        active_config = config or self.config

        skip_reason = _skip_reason(active_config)
        if skip_reason:
            return _fallback(finding, active_config.llm.model, skip_reason)

        payload = _build_remediation_payload(finding, active_config, classification, ranking)
        try:
            result = self.remediator(payload, active_config)
            return _validated_remediation(result, finding, active_config.llm.model)
        except Exception as exc:  # noqa: BLE001 - any failure falls back to template steps.
            return _fallback(finding, active_config.llm.model, str(exc))


def _skip_reason(config: CredHunterConfig) -> str | None:
    if not config.llm.remediate:
        return "LLM remediation is disabled in configuration."
    return llm_ready(config)


def _fallback(finding: NormalizedFinding, model: str, skipped_reason: str) -> LLMRemediation:
    return LLMRemediation(
        steps=remediation_steps(finding.secret_type),
        model=model,
        used=False,
        skipped_reason=skipped_reason,
    )


def _build_remediation_payload(
    finding: NormalizedFinding,
    config: CredHunterConfig,
    classification: LLMClassification | None,
    ranking: LLMRanking | None,
) -> dict[str, Any]:
    payload = build_llm_payload(finding, config)
    payload["template_steps"] = remediation_steps(finding.secret_type)
    if classification and classification.used:
        payload["llm_classification"] = {
            "classification": classification.classification,
            "confidence": classification.confidence,
        }
    if ranking:
        payload["risk"] = {"score": ranking.score, "risk_level": ranking.risk_level}
    return payload


def _validated_remediation(
    result: dict[str, Any],
    finding: NormalizedFinding,
    model: str,
) -> LLMRemediation:
    raw_steps = result.get("steps")
    steps: list[str] = []
    if isinstance(raw_steps, list):
        for item in raw_steps:
            text = str(item).strip()[:MAX_STEP_LENGTH]
            if text:
                steps.append(text)

    if not steps:
        return _fallback(finding, model, "LLM returned no usable remediation steps.")

    metadata = result.get("metadata")
    return LLMRemediation(
        steps=steps[:MAX_STEPS],
        model=model,
        used=True,
        metadata=metadata if isinstance(metadata, dict) else {},
    )


def _openai_remediator(payload: dict[str, Any], config: CredHunterConfig) -> dict[str, Any]:
    return openai_json_call(
        config=config,
        instructions=_remediation_instructions(),
        payload=payload,
        max_output_tokens=350,
    )


def _remediation_instructions() -> str:
    return (
        "You are the remediation stage of a secret-scanner triage pipeline. You receive a redacted "
        "finding, its classification, its risk score, and a set of generic template steps. Produce "
        "two to four concrete, ordered remediation steps tailored to this secret type and file "
        "location (for example: revoke/rotate the specific credential, remove it from the file and "
        "git history, move it to the appropriate secret store). Prefer specificity over the generic "
        "templates. Never require, infer, or repeat the raw secret. Return only valid JSON with key: "
        "steps (an array of short strings)."
    )
