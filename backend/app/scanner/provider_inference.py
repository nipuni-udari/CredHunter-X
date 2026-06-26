from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .models import NormalizedFinding


@dataclass(frozen=True, slots=True)
class RiskFloor:
    provider: str
    minimum_score: int
    minimum_severity: str
    reason: str


GITHUB_TOKEN_RE = re.compile(r"(?i)\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_*.#-]{4,}|\bgithub_pat_")
AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9*.#-]{4,}")
OPENAI_KEY_RE = re.compile(r"(?i)\bsk-(?:proj-)?[A-Za-z0-9*.#_-]{4,}|\bsk-[A-Za-z0-9*.#_-]{4,}")
DATABASE_URL_RE = re.compile(r"(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^/\s:@]+:[^/\s:@]+@")
BEARER_RE = re.compile(r"(?i)\b(?:authorization\b.*\bbearer\b|\bbearer\s+[A-Za-z0-9_*.#=.-]{4,})")

PROVIDER_FLOORS: dict[str, RiskFloor] = {
    "private_key": RiskFloor("private_key", 95, "critical", "Private keys are directly reusable credentials."),
    "github_token": RiskFloor("github_token", 90, "critical", "GitHub tokens can grant repository or account access."),
    "aws_access_key_id": RiskFloor("aws_access_key_id", 90, "critical", "AWS access keys can grant cloud account access."),
    "aws_access_key": RiskFloor("aws_access_key_id", 90, "critical", "AWS access keys can grant cloud account access."),
    "openai_api_key": RiskFloor("openai_api_key", 85, "critical", "OpenAI API keys can incur cost and expose account resources."),
    "database_url": RiskFloor("database_url", 80, "critical", "Database URLs with embedded credentials can expose stored data."),
    "bearer_token": RiskFloor("bearer_token", 75, "high", "Bearer tokens can grant authenticated API access."),
    "oauth_token": RiskFloor("bearer_token", 75, "high", "Bearer or OAuth tokens can grant authenticated API access."),
    "generic_high_entropy_secret": RiskFloor("generic_high_entropy_secret", 65, "high", "High-entropy generic secrets are likely usable credentials."),
}

SEVERITY_MINIMUM_SCORE = {"low": 0, "medium": 30, "high": 60, "critical": 80}
SPECIFICITY = {
    "generic_secret": 0,
    "generic_high_entropy_secret": 1,
    "oauth_token": 2,
    "bearer_token": 3,
    "database_url": 3,
    "openai_api_key": 4,
    "aws_access_key": 4,
    "aws_access_key_id": 4,
    "github_token": 4,
    "private_key": 5,
}


def apply_provider_inference(finding: NormalizedFinding) -> NormalizedFinding:
    """Annotate generic findings with provider-specific type signals.

    The inference uses only safe evidence: the current type/rule id, masked
    target line, detector metadata, and the redacted prefix/suffix. Raw secret
    values are not stored or logged.
    """

    inferred = infer_secret_type(finding)
    if inferred and _is_more_specific(inferred, finding.secret_type):
        previous = finding.secret_type
        finding.secret_type = inferred
        finding.metadata.setdefault("inferred_secret_types", [])
        _append_unique(finding.metadata["inferred_secret_types"], inferred)
        finding.metadata["provider_inference"] = {
            "from": previous,
            "to": inferred,
            "source": "provider_signals",
        }
    elif inferred and inferred != finding.secret_type:
        finding.metadata.setdefault("provider_annotations", [])
        _append_unique(finding.metadata["provider_annotations"], inferred)
    return finding


def infer_secret_type(finding: NormalizedFinding) -> str | None:
    text = _evidence_text(finding)
    lowered_type = (finding.secret_type or "").lower()
    lowered_rule = (finding.rule_id or "").lower()

    if lowered_type == "private_key" or "private-key" in lowered_rule or "private_key" in lowered_rule:
        return "private_key"
    if "github" in lowered_type or "github" in lowered_rule or GITHUB_TOKEN_RE.search(text) or "github_token" in text.lower():
        return "github_token"
    if (
        lowered_type in {"aws_access_key", "aws_access_key_id"}
        or "aws" in lowered_rule
        or AWS_ACCESS_KEY_RE.search(text)
        or "aws_access_key_id" in text.lower()
    ):
        return "aws_access_key_id"
    if lowered_type == "openai_api_key" or "openai" in lowered_rule or OPENAI_KEY_RE.search(text) or "openai_api_key" in text.lower():
        return "openai_api_key"
    if lowered_type == "database_url" or DATABASE_URL_RE.search(text) or ("database_url" in text.lower() and "@" in text):
        return "database_url"
    if lowered_type in {"bearer_token", "oauth_token"} or BEARER_RE.search(text):
        return "bearer_token"
    if lowered_type == "generic_high_entropy_secret":
        return "generic_high_entropy_secret"
    return None


def provider_floor_for_finding(finding: NormalizedFinding) -> RiskFloor | None:
    inferred = infer_secret_type(finding) or finding.secret_type
    return PROVIDER_FLOORS.get(inferred) or PROVIDER_FLOORS.get(finding.secret_type)


def apply_score_floor(score: int, floor: RiskFloor | None) -> tuple[int, RiskFloor | None]:
    if not floor:
        return score, None
    severity_floor = SEVERITY_MINIMUM_SCORE.get(floor.minimum_severity, 0)
    minimum = max(floor.minimum_score, severity_floor)
    if score >= minimum:
        return score, None
    return minimum, floor


def risk_floor_metadata(floor: RiskFloor | None) -> dict[str, Any] | None:
    if not floor:
        return None
    return {
        "provider": floor.provider,
        "minimum_score": floor.minimum_score,
        "minimum_severity": floor.minimum_severity,
        "applied": True,
        "reason": floor.reason,
    }


def _is_more_specific(candidate: str, current: str) -> bool:
    return SPECIFICITY.get(candidate, 0) > SPECIFICITY.get(current, 0)


def _append_unique(values: list, value: str) -> None:
    if value not in values:
        values.append(value)


def _evidence_text(finding: NormalizedFinding) -> str:
    metadata = finding.metadata or {}
    parts: list[str] = [
        finding.secret_type or "",
        finding.rule_id or "",
        finding.description or "",
        finding.detector or "",
        finding.redacted_secret or "",
        str(metadata.get("target_line") or ""),
        str(metadata.get("masked_target_line") or ""),
        str(metadata.get("message") or ""),
        str(metadata.get("candidate_type") or ""),
        str(metadata.get("variable") or ""),
    ]
    parts.extend(str(item) for item in _list(metadata.get("merged_secret_types")))
    parts.extend(str(item) for item in _list(metadata.get("merged_rule_ids")))
    return " ".join(parts)


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    return [value]
