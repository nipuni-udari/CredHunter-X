from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .models import NormalizedFinding, RawFinding
from .redaction import hash_secret, redact_secret

_HEX_RE = re.compile(r"^[0-9a-f]+$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
# Common non-secret digest lengths: md5(32), sha1(40), sha224(56), sha256(64), sha384(96), sha512(128).
_HASH_LENGTHS = {32, 40, 56, 64, 96, 128}


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
    stripped = value.strip()
    return {
        "length": len(stripped),
        "placeholder": _has_placeholder(lowered),
        "local_only_database_url": _is_local_database_url(lowered),
        "repeated_or_low_value": _is_repeated_or_low_value(lowered),
        "uuid_like": bool(_UUID_RE.match(lowered)),
        "hash_like": _is_hash_like(stripped),
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
    if len(compact) < 4:
        return False
    # Single repeated character, e.g. "aaaaaaaa" or "00000000".
    if len(set(compact)) == 1:
        return True
    # Short repeating unit, e.g. "abcabcabc" or "12341234".
    for unit in (1, 2, 3, 4):
        if len(compact) > unit and len(compact) % unit == 0:
            if compact == compact[:unit] * (len(compact) // unit):
                return True
    # Monotonic ascending/descending run, e.g. "123456789" or "abcdef".
    if _is_sequential(compact):
        return True
    return False


def _is_sequential(value: str) -> bool:
    if len(value) < 5:
        return False
    deltas = {ord(b) - ord(a) for a, b in zip(value, value[1:])}
    return deltas in ({1}, {-1})


def _is_hash_like(value: str) -> bool:
    return len(value) in _HASH_LENGTHS and bool(_HEX_RE.match(value.lower()))
