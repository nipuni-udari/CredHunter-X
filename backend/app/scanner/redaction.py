from __future__ import annotations

import hashlib
import hmac
import os


DEFAULT_HASH_KEY = "credhunter-x-development-key"


def redact_secret(secret: str | None) -> str | None:
    if not secret:
        return None

    cleaned = secret.strip()
    if len(cleaned) <= 8:
        return "****"

    if "\n" in cleaned or "PRIVATE KEY" in cleaned:
        lines = cleaned.splitlines()
        if len(lines) >= 2 and lines[0].startswith("-----BEGIN"):
            return f"{lines[0]}\n****\n{lines[-1]}"
        return "****"

    prefix = cleaned[:4]
    suffix = cleaned[-4:]
    return f"{prefix}****{suffix}"


def hash_secret(secret: str | None, key: str | None = None) -> str | None:
    if not secret:
        return None

    hash_key = key or os.getenv("CREDHUNTER_HASH_KEY", DEFAULT_HASH_KEY)
    digest = hmac.new(
        hash_key.encode("utf-8"),
        secret.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"hmac-sha256:{digest}"
