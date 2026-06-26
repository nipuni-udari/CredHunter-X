"""LLM Ranker stage.

The second stage of the LLM pipeline (classify -> rank -> explain -> remediate).
It takes a finding together with its LLM classification and the deterministic
rule-based risk score, and asks the model to produce a refined 0-100 risk score
that prioritises findings for the developer. The model only proposes the score
and a short rationale; the risk level and CI action are derived from that score
with the same thresholds the deterministic ranker uses, so downstream decision
logic stays consistent regardless of which ranker produced the score.

The stage is conservative and self-contained:

- It never runs unless ``llm.enabled`` and ``llm.rank`` are both set and an API
  key is present; otherwise it returns an unused result and the deterministic
  score stands.
- It never lowers a private-key finding below critical.
- Any error falls back to the deterministic score (``used=False``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from app.ci.config import CredHunterConfig
from app.scanner.models import NormalizedFinding
from app.scanner.provider_inference import (
    apply_provider_inference,
    apply_score_floor,
    provider_floor_for_finding,
    risk_floor_metadata,
)
from app.services.false_positive_filter import assess_false_positive
from app.services.llm_client import llm_ready, openai_json_call
from app.services.llm_filter_service import LLMClassification, build_llm_payload
from app.services.risk_scoring_service import (
    RiskScore,
    recommended_action_for_level,
    risk_level_from_score,
    score_finding,
)

Ranker = Callable[[dict[str, Any], CredHunterConfig], dict[str, Any]]

RANKER_SCHEMA = {
    "type": "object",
    "properties": {
        "risk_score": {"type": "integer", "minimum": 0, "maximum": 100},
        "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
        "reason": {"type": "string"},
    },
    "required": ["risk_score", "severity", "reason"],
    "additionalProperties": False,
}


@dataclass(slots=True)
class LLMRanking:
    score: int
    risk_level: str
    recommended_action: str
    rationale: str
    model: str
    used: bool
    skipped_reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_metadata(self) -> dict:
        return {
            "score": self.score,
            "risk_level": self.risk_level,
            "recommended_action": self.recommended_action,
            "rationale": self.rationale,
            "model": self.model,
            "used": self.used,
            "skipped_reason": self.skipped_reason,
            "metadata": self.metadata,
        }


class LLMRankerService:
    def __init__(self, config: CredHunterConfig, ranker: Ranker | None = None) -> None:
        self.config = config
        self.ranker = ranker or _openai_ranker

    def rank_findings(
        self,
        findings: list[NormalizedFinding],
        classifications: dict[str, LLMClassification] | None = None,
        config: CredHunterConfig | None = None,
    ) -> dict[str, LLMRanking]:
        active_config = config or self.config
        classifications = classifications or {}
        rankings: dict[str, LLMRanking] = {}
        for finding in findings:
            ranking = self.rank_finding(
                finding, classifications.get(finding.finding_id), active_config
            )
            if ranking:
                rankings[finding.finding_id] = ranking
        return rankings

    def rank_finding(
        self,
        finding: NormalizedFinding,
        classification: LLMClassification | None = None,
        config: CredHunterConfig | None = None,
    ) -> LLMRanking | None:
        active_config = config or self.config
        apply_provider_inference(finding)

        skip_reason = _skip_reason(finding, active_config)
        base_score = _deterministic_score(finding, active_config, classification)
        if skip_reason:
            return _fallback_ranking(base_score, active_config.llm.model, skip_reason)

        payload = _build_rank_payload(finding, active_config, classification, base_score)
        try:
            result = self.ranker(payload, active_config)
            return _validated_ranking(result, finding, base_score, classification, active_config)
        except Exception as exc:  # noqa: BLE001 - any failure falls back to deterministic.
            return _fallback_ranking(base_score, active_config.llm.model, str(exc))


def _skip_reason(finding: NormalizedFinding, config: CredHunterConfig) -> str | None:
    if assess_false_positive(finding, config).ignored:
        return "Deterministic rule already classified finding as an obvious false positive."
    if not config.llm.rank:
        return "LLM ranking is disabled in configuration."
    return llm_ready(config)


def _deterministic_score(
    finding: NormalizedFinding,
    config: CredHunterConfig,
    classification: LLMClassification | None,
) -> RiskScore:
    assessment = assess_false_positive(finding, config)
    return score_finding(finding, config, assessment, classification)


def _fallback_ranking(base_score: RiskScore, model: str, skipped_reason: str) -> LLMRanking:
    is_local_skip = "classified finding as an obvious false positive" in skipped_reason
    return LLMRanking(
        score=base_score.score,
        risk_level=base_score.risk_level,
        recommended_action=base_score.recommended_action,
        rationale="Deterministic risk score retained.",
        model=model,
        used=False,
        skipped_reason=skipped_reason,
        metadata={"fallback": not is_local_skip, "error": skipped_reason} if not is_local_skip else {"fallback": False, "skipped": True},
    )


def _build_rank_payload(
    finding: NormalizedFinding,
    config: CredHunterConfig,
    classification: LLMClassification | None,
    base_score: RiskScore,
) -> dict[str, Any]:
    payload = build_llm_payload(finding, config)
    payload["rule_based_risk"] = {
        "score": base_score.score,
        "risk_level": base_score.risk_level,
        "components": [component.to_dict() for component in base_score.components],
    }
    if classification and classification.used:
        payload["llm_classification"] = {
            "classification": classification.classification,
            "confidence": classification.confidence,
            "reason": classification.reason,
            "recommended_action": classification.recommended_action,
        }
    return payload


def _validated_ranking(
    result: dict[str, Any],
    finding: NormalizedFinding,
    base_score: RiskScore,
    classification: LLMClassification | None,
    config: CredHunterConfig,
) -> LLMRanking:
    if "risk_score" not in result and "score" not in result:
        raise ValueError("LLM ranker response did not match the expected schema.")
    score = _clamp_score(result.get("risk_score", result.get("score")), base_score.score)
    applied_floor = None
    provider_floor = provider_floor_for_finding(finding)
    if not _classification_suppresses_floor(finding, classification, config):
        score, applied_floor = apply_score_floor(score, provider_floor)
    score, score_cap = _apply_generic_secret_cap(finding, base_score, score, provider_floor)
    score, high_floor_cap = _apply_high_floor_provider_cap(base_score, score, provider_floor)

    metadata = result.get("metadata") if isinstance(result.get("metadata"), dict) else {}
    model_severity = str(result.get("severity", "")).lower()
    risk_level = risk_level_from_score(score)
    if model_severity in {"low", "medium", "high", "critical"} and model_severity != risk_level:
        metadata = dict(metadata)
        metadata["model_severity"] = model_severity
        metadata["severity_normalized"] = risk_level
    floor_metadata = risk_floor_metadata(applied_floor)
    if floor_metadata:
        metadata = dict(metadata)
        metadata["risk_floor"] = floor_metadata
    if score_cap:
        metadata = dict(metadata)
        metadata["score_cap"] = score_cap
    if high_floor_cap:
        metadata = dict(metadata)
        metadata["high_floor_cap"] = high_floor_cap
    return LLMRanking(
        score=score,
        risk_level=risk_level,
        recommended_action=recommended_action_for_level(risk_level),
        rationale=str(result.get("reason", result.get("rationale", "No rationale supplied.")))[:500],
        model=config.llm.model,
        used=True,
        metadata=metadata,
    )


def _apply_generic_secret_cap(
    finding: NormalizedFinding,
    base_score: RiskScore,
    score: int,
    provider_floor: Any,
) -> tuple[int, dict[str, Any] | None]:
    if provider_floor is not None:
        return score, None
    if finding.secret_type != "generic_secret":
        return score, None
    if base_score.risk_level not in {"low", "medium"}:
        return score, None
    if score <= 59:
        return score, None
    return 59, {
        "type": "generic_secret_without_provider_floor",
        "original_score": score,
        "capped_score": 59,
        "reason": "Plain generic secrets without provider evidence stay within the medium band.",
    }


def _apply_high_floor_provider_cap(
    base_score: RiskScore,
    score: int,
    provider_floor: Any,
) -> tuple[int, dict[str, Any] | None]:
    if provider_floor is None:
        return score, None
    if provider_floor.minimum_severity != "high":
        return score, None
    if base_score.risk_level == "critical":
        return score, None
    if score <= 79:
        return score, None
    return 79, {
        "type": "high_floor_provider_without_active_validation",
        "provider": provider_floor.provider,
        "original_score": score,
        "capped_score": 79,
        "reason": "High-floor provider token without active validation stays within the high band.",
    }


def _classification_suppresses_floor(
    finding: NormalizedFinding,
    classification: LLMClassification | None,
    config: CredHunterConfig,
) -> bool:
    if finding.secret_type == "private_key":
        return False
    return bool(
        classification
        and classification.used
        and classification.confidence >= config.llm.min_confidence
        and classification.classification in {"likely_false_positive", "false_positive"}
    )


def _openai_ranker(payload: dict[str, Any], config: CredHunterConfig) -> dict[str, Any]:
    return openai_json_call(
        config=config,
        instructions=_rank_instructions(),
        payload=payload,
        max_output_tokens=300,
        schema_name="credhunter_ranker",
        schema=RANKER_SCHEMA,
    )


def _rank_instructions() -> str:
    return (
        "You are the ranking stage of a secret-scanner triage pipeline. You receive a "
        "redacted finding, the deterministic rule-based risk score, and (optionally) an LLM "
        "classification. Assign a final risk score from 0 to 100 that reflects how urgently a "
        "developer should act, where higher means more dangerous. Treat the rule-based score as a "
        "strong prior and adjust it using the classification and context. Never require or infer "
        "the raw secret. Provider tokens and private keys have deterministic minimum floors that "
        "will be enforced after your score. Return a structured result with keys: "
        "risk_score (integer 0-100), severity, reason. Severity must match the "
        "score band: low 0-29, medium 30-59, high 60-79, critical 80-100. "
        "Plain generic_secret findings without provider-specific evidence should normally stay "
        "in the medium band unless deterministic context already makes them high risk. "
        "Be conservative: do not lower the score for provider tokens in source/config files unless "
        "the context is clearly documentation, placeholder, test fixture, or local-only."
    )


def _clamp_score(value: Any, default: int) -> int:
    try:
        parsed = int(round(float(value)))
    except (TypeError, ValueError):
        return default
    return max(0, min(100, parsed))
