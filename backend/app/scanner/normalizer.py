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
        metadata=_safe_metadata(raw.metadata),
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


def _safe_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    blocked_keys = {"secret", "raw_secret", "match", "matched_text"}
    return {key: value for key, value in metadata.items() if key.lower() not in blocked_keys}
