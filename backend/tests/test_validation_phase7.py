import base64
import json
import time
import unittest

from fastapi.testclient import TestClient

from app.api.app import create_app
from app.ci.config import CredHunterConfig
from app.scanner.models import RawFinding
from app.scanner.normalizer import normalize_finding
from app.services.validation_service import ValidationService


class ValidationPhase7Tests(unittest.TestCase):
    def test_validation_disabled_is_skipped(self):
        finding = _github_finding()

        result = ValidationService(CredHunterConfig()).validate_finding(finding, raw_secret="fake-token")

        self.assertEqual(result.status, "skipped")
        self.assertFalse(result.checked)

    def test_github_validation_uses_fake_requester(self):
        config = CredHunterConfig()
        config.validation.enabled = True
        config.validation.network_enabled = True

        service = ValidationService(config, github_requester=lambda token, timeout: 200)
        result = service.validate_finding(_github_finding(), raw_secret="fake-token")

        self.assertEqual(result.status, "valid")
        self.assertTrue(result.active)
        self.assertTrue(result.network_used)

    def test_jwt_expired_validation_is_local(self):
        config = CredHunterConfig()
        config.validation.enabled = True
        expired_jwt = _jwt({"exp": int(time.time()) - 60})
        finding = normalize_finding(
            RawFinding(
                detector="regex.jwt",
                secret_type="jwt",
                file_path="src/auth.py",
                raw_secret=expired_jwt,
                confidence=0.72,
                source="test",
            )
        )

        result = ValidationService(config).validate_finding(finding, raw_secret=expired_jwt)

        self.assertEqual(result.status, "expired")
        self.assertFalse(result.active)
        self.assertFalse(result.network_used)

    def test_database_url_local_only_validation(self):
        config = CredHunterConfig()
        config.validation.enabled = True
        raw_url = "mongodb://localhost:27017/app"
        finding = normalize_finding(
            RawFinding(
                detector="regex.database_url",
                secret_type="database_url",
                file_path=".env",
                raw_secret=raw_url,
                confidence=0.82,
                source="test",
            )
        )

        result = ValidationService(config).validate_finding(finding, raw_secret=raw_url)

        self.assertEqual(result.status, "local_only")
        self.assertFalse(result.active)

    def test_api_validate_endpoint_does_not_store_raw_secret(self):
        client = TestClient(create_app())
        raw_secret = "mongodb://localhost:27017/app"
        response = client.post(
            "/api/findings/validate",
            json={
                "finding": {
                    "detector": "regex.database_url",
                    "secret_type": "database_url",
                    "file_path": ".env",
                    "line_number": 1,
                    "redacted_secret": "mong****/app",
                    "secret_hash": "hmac-sha256:test",
                    "confidence": 0.82,
                    "source": "test",
                },
                "raw_secret": raw_secret,
                "config": {"validation": {"enabled": True}},
            },
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "local_only")
        self.assertNotIn(raw_secret, json.dumps(body))


def _github_finding():
    return normalize_finding(
        RawFinding(
            detector="regex.github_token",
            secret_type="github_token",
            file_path="src/config.py",
            raw_secret="ghp_fakegithubtokenvalue123456",
            confidence=0.9,
            source="test",
        )
    )


def _jwt(payload: dict) -> str:
    header = {"alg": "none", "typ": "JWT"}
    return ".".join([_b64(header), _b64(payload), "signature"])


def _b64(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


if __name__ == "__main__":
    unittest.main()
