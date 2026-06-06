from __future__ import annotations

import hashlib
import json
from typing import Any

from .models import NormalizedFinding, RawFinding
from .redaction import hash_secret, redact_secret


def normalize_finding(raw: RawFinding) -> NormalizedFinding:
    redacted_secret = redact_secret(raw.raw_secret)
    secret_hash = hash_secret(raw.raw_secret)
    finding_id = _build_finding_id(raw, secret_hash)

    return NormalizedFinding(
        finding_id=finding_id,
        detector=raw.detector,
        secret_type=raw.secret_type,
        file_path=raw.file_path,
        line_number=raw.line_number,
        redacted_secret=redacted_secret,
        secret_hash=secret_hash,
        confidence=_clamp(raw.confidence),
        entropy=raw.entropy,
        commit_sha=raw.commit_sha,
        rule_id=raw.rule_id,
        description=raw.description,
        context_before=raw.context_before,
        context_after=raw.context_after,
        source=raw.source,
        metadata=_safe_metadata(raw),
    )


def _build_finding_id(raw: RawFinding, secret_hash: str | None) -> str:
    identity = {
        "detector": raw.detector,
        "secret_type": raw.secret_type,
        "file_path": raw.file_path,
        "line_number": raw.line_number,
        "secret_hash": secret_hash,
        "rule_id": raw.rule_id,
        "commit_sha": raw.commit_sha,
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:24]


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


def _safe_metadata(raw: RawFinding) -> dict[str, Any]:
    blocked_keys = {"secret", "raw_secret", "match", "matched_text"}
    metadata = {key: value for key, value in raw.metadata.items() if key.lower() not in blocked_keys}
    metadata["secret_indicators"] = _secret_indicators(raw)
    return metadata


def _secret_indicators(raw: RawFinding) -> dict[str, bool | int | str | None]:
    value = raw.raw_secret or raw.matched_text or ""
    lowered = value.lower()
    return {
        "length": len(value),
        "placeholder": _has_placeholder(lowered),
        "local_only_database_url": _is_local_database_url(lowered),
        "repeated_or_low_value": _is_repeated_or_low_value(lowered),
        "has_private_key_marker": "private key" in lowered,
    }


def _has_placeholder(value: str) -> bool:
    placeholders = (
        "example",
        "dummy",
        "sample",
        "changeme",
        "placeholder",
        "your_api_key",
        "your-api-key",
        "your_token",
        "replace_me",
        "replace-me",
        "000000",
    )
    return any(item in value for item in placeholders)


def _is_local_database_url(value: str) -> bool:
    return any(
        marker in value
        for marker in (
            "mongodb://localhost",
            "mongodb://127.0.0.1",
            "postgres://localhost",
            "postgresql://localhost",
            "mysql://localhost",
            "redis://localhost",
            "@localhost",
            "@127.0.0.1",
        )
    )


def _is_repeated_or_low_value(value: str) -> bool:
    compact = value.replace("-", "").replace("_", "")
    if not compact:
        return False
    repeated_values = {"0", "1", "a", "x"}
    return len(set(compact)) == 1 and compact[0] in repeated_values
