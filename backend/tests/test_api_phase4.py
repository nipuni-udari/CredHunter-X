import unittest

from fastapi.testclient import TestClient

from app.api.app import create_app
from app.api.dependencies import set_repository
from app.repositories.memory_repository import InMemoryRepository


class APIPhase4Tests(unittest.TestCase):
    def setUp(self):
        set_repository(InMemoryRepository())
        self.client = TestClient(create_app())

    def tearDown(self):
        set_repository(None)

    def test_health_check(self):
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    def test_create_scan_get_scan_and_list_findings(self):
        payload = _scan_payload()

        create_response = self.client.post("/api/scans", json=payload)

        self.assertEqual(create_response.status_code, 201)
        created = create_response.json()
        self.assertEqual(created["decision"]["action"], "fail")
        self.assertEqual(created["decision"]["blocking_count"], 1)
        self.assertEqual(len(created["findings"]), 1)

        scan_id = created["scan_id"]
        get_response = self.client.get(f"/api/scans/{scan_id}")
        self.assertEqual(get_response.status_code, 200)
        self.assertEqual(get_response.json()["scan_id"], scan_id)

        findings_response = self.client.get("/api/projects/project-demo/findings")
        self.assertEqual(findings_response.status_code, 200)
        self.assertEqual(findings_response.json()["finding_count"], 1)

    def test_classify_finding(self):
        response = self.client.post(
            "/api/findings/classify",
            json={
                "finding": _finding_payload(),
                "config": {"scan": {"fail_on": "critical"}},
            },
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["risk_level"], "high")
        self.assertEqual(body["action"], "manual_review")
        self.assertIn("risk_score", body)

    def test_suppress_and_mark_finding(self):
        created = self.client.post("/api/scans", json=_scan_payload()).json()
        finding_id = created["findings"][0]["finding_id"]

        suppress_response = self.client.post(
            f"/api/findings/{finding_id}/suppress",
            json={"user": "tester", "reason": "known test fixture", "scope": "finding"},
        )
        self.assertEqual(suppress_response.status_code, 200)
        self.assertTrue(suppress_response.json()["suppressed"])

        feedback_response = self.client.post(
            f"/api/findings/{finding_id}/mark-false-positive",
            json={"user": "tester", "reason": "dummy value"},
        )
        self.assertEqual(feedback_response.status_code, 200)
        self.assertEqual(feedback_response.json()["feedback"]["label"], "false_positive")


def _scan_payload():
    return {
        "project_id": "project-demo",
        "repository_id": "repo-demo",
        "repository_name": "demo/repo",
        "provider": "github",
        "branch": "main",
        "commit_sha": "abc123",
        "pull_request_number": 10,
        "github_run_id": "1001",
        "findings": [_finding_payload()],
        "config": {
            "scan": {"mode": "changed-files", "fail_on": "high", "include_history": False},
            "filters": {"ignore_paths": [], "allow_placeholders": True},
            "backend": {"url": None},
        },
    }


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


if __name__ == "__main__":
    unittest.main()
