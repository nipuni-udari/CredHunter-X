import json
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from app.api.app import create_app
from app.api.dependencies import set_repository
from app.ci.cli import main as ci_main
from app.ci.config import CredHunterConfig
from app.ci.decision import evaluate_findings
from app.repositories.memory_repository import InMemoryRepository
from app.reporting.markdown import build_feedback_summary, build_pr_comment
from app.scanner.models import RawFinding
from app.scanner.normalizer import normalize_finding


class ReportingPhase11Tests(unittest.TestCase):
    def setUp(self):
        set_repository(InMemoryRepository())
        self.client = TestClient(create_app())

    def tearDown(self):
        set_repository(None)

    def test_build_pr_comment_contains_counts_and_remediation(self):
        config = CredHunterConfig()
        config.scan.fail_on = "critical"
        decision = evaluate_findings([_github_finding()], config)

        markdown = build_pr_comment(decision)

        self.assertIn("CredHunter-X Report", markdown)
        self.assertIn("GitHub token", markdown)
        self.assertIn("Revoke or rotate the GitHub token.", markdown)
        self.assertIn("manual_review", markdown)

    def test_cli_writes_pr_comment_output(self):
        output_dir = Path("tests/fixtures/generated")
        output_path = output_dir / "phase11-pr-comment.md"

        exit_code = ci_main(
            [
                "--gitleaks-report",
                "tests/fixtures/gitleaks-report.json",
                "--config",
                "tests/fixtures/credhunter.yml",
                "--fail-on",
                "critical",
                "--json-output",
                str(output_dir / "phase11-report.json"),
                "--sarif-output",
                str(output_dir / "phase11-report.sarif"),
                "--pr-comment-output",
                str(output_path),
            ]
        )

        self.assertEqual(exit_code, 0)
        self.assertTrue(output_path.exists())
        self.assertIn("CredHunter-X Report", output_path.read_text(encoding="utf-8"))

    def test_scan_pr_comment_endpoint(self):
        created = self.client.post("/api/scans", json=_scan_payload()).json()

        response = self.client.get(f"/api/scans/{created['scan_id']}/pr-comment")

        self.assertEqual(response.status_code, 200)
        self.assertIn("CredHunter-X Report", response.json()["markdown"])

    def test_feedback_summary_endpoint(self):
        created = self.client.post("/api/scans", json=_scan_payload()).json()
        finding_id = created["findings"][0]["finding_id"]
        self.client.post(
            f"/api/findings/{finding_id}/mark-true-positive",
            json={"user": "reviewer", "reason": "confirmed"},
        )

        response = self.client.get("/api/projects/project-reporting/feedback-summary")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["true_positive_count"], 1)
        self.assertEqual(body["finding_count"], 1)

    def test_build_feedback_summary_counts_suppressed_and_labels(self):
        summary = build_feedback_summary(
            [
                {"finding_id": "a", "suppressed": True, "feedback": None},
                {"finding_id": "b", "feedback": {"label": "false_positive"}},
                {"finding_id": "c", "feedback": {"label": "true_positive"}},
            ]
        )

        self.assertEqual(summary["suppressed_count"], 1)
        self.assertEqual(summary["false_positive_count"], 1)
        self.assertEqual(summary["true_positive_count"], 1)


def _github_finding():
    return normalize_finding(
        RawFinding(
            detector="regex.github_token",
            secret_type="github_token",
            file_path="src/config.py",
            raw_secret="ghp_1234567890abcdef1234567890",
            confidence=0.9,
            source="test",
        )
    )


def _scan_payload():
    return {
        "project_id": "project-reporting",
        "repository_id": "repo-reporting",
        "repository_name": "demo/reporting",
        "provider": "github",
        "findings": [_github_finding().to_dict()],
        "config": {"scan": {"fail_on": "critical"}},
    }


if __name__ == "__main__":
    unittest.main()
