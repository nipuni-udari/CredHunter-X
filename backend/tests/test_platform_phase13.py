import os
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from app.api.app import create_app
from app.api.dependencies import set_job_queue, set_repository
from app.repositories.memory_repository import InMemoryRepository
from app.services.job_queue import InlineJobQueue


def _finding_payload():
    return {
        "detector": "gitleaks",
        "secret_type": "github_token",
        "file_path": "src/config.py",
        "line_number": 7,
        "redacted_secret": "ghp_****7890",
        "secret_hash": "hmac-sha256:test-hash",
        "confidence": 0.85,
        "rule_id": "github-pat",
        "source": "gitleaks_json",
    }


def _scan_payload():
    return {
        "project_id": "project-demo",
        "repository_id": "repo-demo",
        "repository_name": "demo/repo",
        "provider": "github",
        "findings": [_finding_payload()],
        "config": {"scan": {"fail_on": "high"}},
    }


class ApiKeyAuthTests(unittest.TestCase):
    def setUp(self):
        set_repository(InMemoryRepository())

    def tearDown(self):
        set_repository(None)

    def test_auth_disabled_when_no_keys_configured(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CREDHUNTER_API_KEYS", None)
            client = TestClient(create_app())
            response = client.post("/api/scans", json=_scan_payload())
        self.assertEqual(response.status_code, 201)

    def test_request_rejected_without_valid_key(self):
        with mock.patch.dict(os.environ, {"CREDHUNTER_API_KEYS": "secret-key-1,secret-key-2"}):
            client = TestClient(create_app())

            missing = client.post("/api/scans", json=_scan_payload())
            self.assertEqual(missing.status_code, 401)

            wrong = client.post("/api/scans", json=_scan_payload(), headers={"X-API-Key": "nope"})
            self.assertEqual(wrong.status_code, 401)

    def test_request_accepted_with_valid_key(self):
        with mock.patch.dict(os.environ, {"CREDHUNTER_API_KEYS": "secret-key-1,secret-key-2"}):
            client = TestClient(create_app())
            response = client.post(
                "/api/scans",
                json=_scan_payload(),
                headers={"X-API-Key": "secret-key-2"},
            )
        self.assertEqual(response.status_code, 201)

    def test_health_endpoints_remain_open(self):
        with mock.patch.dict(os.environ, {"CREDHUNTER_API_KEYS": "secret-key-1"}):
            client = TestClient(create_app())
            self.assertEqual(client.get("/health").status_code, 200)
            self.assertEqual(client.get("/health/ready").status_code, 200)


class AsyncScanQueueTests(unittest.TestCase):
    def setUp(self):
        set_repository(InMemoryRepository())
        set_job_queue(InlineJobQueue())
        self.client = TestClient(create_app())

    def tearDown(self):
        set_repository(None)
        set_job_queue(None)

    def test_async_scan_processes_inline_and_is_retrievable(self):
        response = self.client.post("/api/scans/async", json=_scan_payload())

        self.assertEqual(response.status_code, 202)
        body = response.json()
        self.assertEqual(body["status"], "finished")
        self.assertIsNotNone(body["result"])

        scan_id = body["result"]["scan_id"]

        job_response = self.client.get(f"/api/jobs/{body['job_id']}")
        self.assertEqual(job_response.status_code, 200)
        self.assertEqual(job_response.json()["status"], "finished")

        scan_response = self.client.get(f"/api/scans/{scan_id}")
        self.assertEqual(scan_response.status_code, 200)
        self.assertEqual(scan_response.json()["decision"]["action"], "fail")

    def test_unknown_job_returns_404(self):
        response = self.client.get("/api/jobs/job_does_not_exist")
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
