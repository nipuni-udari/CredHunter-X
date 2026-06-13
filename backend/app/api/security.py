from __future__ import annotations

import hmac
import os

from fastapi import Header, HTTPException, status

API_KEY_HEADER = "X-API-Key"


def configured_api_keys() -> set[str]:
    """Return the set of API keys configured via CREDHUNTER_API_KEYS.

    The value is a comma-separated list. When unset or empty, authentication is
    disabled so local development and the existing test suite keep working.
    """

    raw = os.getenv("CREDHUNTER_API_KEYS", "")
    return {key.strip() for key in raw.split(",") if key.strip()}


def auth_enabled() -> bool:
    return bool(configured_api_keys())


def _is_valid_key(candidate: str, allowed: set[str]) -> bool:
    # Constant-time comparison against each allowed key to avoid timing leaks.
    return any(hmac.compare_digest(candidate, key) for key in allowed)


def require_api_key(x_api_key: str | None = Header(default=None, alias=API_KEY_HEADER)) -> None:
    """FastAPI dependency enforcing API-key auth when keys are configured."""

    allowed = configured_api_keys()
    if not allowed:
        return

    if not x_api_key or not _is_valid_key(x_api_key, allowed):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
            headers={"WWW-Authenticate": API_KEY_HEADER},
        )
