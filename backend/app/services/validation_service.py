from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlparse

from app.ci.config import CredHunterConfig
from app.scanner.models import NormalizedFinding


@dataclass(slots=True)
class ValidationResult:
    provider: str
    status: str
    active: bool | None
    reason: str
    checked: bool
    network_used: bool = False
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "status": self.status,
            "active": self.active,
            "reason": self.reason,
            "checked": self.checked,
            "network_used": self.network_used,
            "metadata": self.metadata,
        }


class ValidationService:
    def __init__(
        self,
        config: CredHunterConfig,
        github_requester: Callable[[str, float], int] | None = None,
    ) -> None:
        self.config = config
        self.github_requester = github_requester or _github_user_status

    def validate_finding(self, finding: NormalizedFinding, raw_secret: str | None = None) -> ValidationResult:
        if not self.config.validation.enabled:
            return ValidationResult(
                provider=_provider_for(finding),
                status="skipped",
                active=None,
                reason="Secret validation is disabled.",
                checked=False,
            )

        provider = _provider_for(finding)
        if provider not in self.config.validation.providers:
            return ValidationResult(
                provider=provider,
                status="unsupported",
                active=None,
                reason="Provider is not enabled for validation.",
                checked=False,
            )

        if provider == "github":
            return self._validate_github(raw_secret)
        if provider == "jwt":
            return _validate_jwt(raw_secret)
        if provider == "database_url":
            return _validate_database_url(raw_secret)

        return ValidationResult(
            provider=provider,
            status="unsupported",
            active=None,
            reason="No validator is implemented for this provider.",
            checked=False,
        )

    def _validate_github(self, raw_secret: str | None) -> ValidationResult:
        if not raw_secret:
            return ValidationResult(
                provider="github",
                status="skipped",
                active=None,
                reason="Raw secret is required for active GitHub token validation.",
                checked=False,
            )
        if not self.config.validation.network_enabled:
            return ValidationResult(
                provider="github",
                status="skipped",
                active=None,
                reason="Network validation is disabled.",
                checked=False,
            )

        status_code = self.github_requester(raw_secret, self.config.validation.timeout_seconds)
        if status_code == 200:
            return ValidationResult("github", "valid", True, "GitHub token authenticated successfully.", True, True)
        if status_code in {401, 403}:
            return ValidationResult("github", "invalid", False, "GitHub token was rejected.", True, True)
        return ValidationResult(
            "github",
            "unknown",
            None,
            f"GitHub validation returned HTTP {status_code}.",
            True,
            True,
        )


def _provider_for(finding: NormalizedFinding) -> str:
    if finding.secret_type == "github_token":
        return "github"
    if finding.secret_type == "jwt":
        return "jwt"
    if finding.secret_type == "database_url":
        return "database_url"
    return finding.secret_type


def _validate_jwt(raw_secret: str | None) -> ValidationResult:
    if not raw_secret:
        return ValidationResult("jwt", "skipped", None, "Raw JWT is required for expiration validation.", False)

    parts = raw_secret.split(".")
    if len(parts) != 3:
        return ValidationResult("jwt", "invalid", False, "JWT does not have three segments.", True)

    try:
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError):
        return ValidationResult("jwt", "invalid", False, "JWT payload could not be decoded.", True)

    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        if exp < time.time():
            return ValidationResult("jwt", "expired", False, "JWT expiration time is in the past.", True)
        return ValidationResult("jwt", "structurally_valid", None, "JWT is not expired, signature not verified.", True)

    return ValidationResult("jwt", "structurally_valid", None, "JWT payload decoded, no exp claim found.", True)


def _validate_database_url(raw_secret: str | None) -> ValidationResult:
    if not raw_secret:
        return ValidationResult(
            "database_url",
            "skipped",
            None,
            "Raw database URL is required for local-only validation.",
            False,
        )

    parsed = urlparse(raw_secret)
    if parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
        return ValidationResult(
            "database_url",
            "local_only",
            False,
            "Database URL targets a local-only host.",
            True,
        )

    if parsed.scheme and parsed.hostname:
        return ValidationResult(
            "database_url",
            "unverified_external",
            None,
            "Database URL is external-looking; no connection attempt was made.",
            True,
        )

    return ValidationResult("database_url", "invalid", False, "Database URL could not be parsed.", True)


def _github_user_status(token: str, timeout: float) -> int:
    request = urllib.request.Request(
        "https://api.github.com/user",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "CredHunter-X",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)
    except urllib.error.URLError:
        return 0


def _b64url_decode(value: str) -> str:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8")
