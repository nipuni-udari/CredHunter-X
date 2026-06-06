import unittest

from app.ci.config import CredHunterConfig
from app.ci.decision import evaluate_findings
from app.scanner.models import RawFinding
from app.scanner.normalizer import normalize_finding
from app.services.false_positive_filter import assess_false_positive


class FalsePositivePhase5Tests(unittest.TestCase):
    def test_placeholder_finding_is_ignored(self):
        finding = normalize_finding(
            RawFinding(
                detector="regex.generic",
                secret_type="generic_high_entropy_secret",
                file_path="docs/example.env",
                raw_secret="your_api_key_here_000000000000",
                confidence=0.7,
                source="test",
            )
        )

        decision = evaluate_findings([finding], CredHunterConfig())

        self.assertEqual(decision.action, "pass")
        self.assertEqual(decision.ignored_count, 1)
        self.assertEqual(decision.findings[0].false_positive_assessment.classification, "false_positive")

    def test_private_key_is_not_downgraded_even_in_docs(self):
        finding = normalize_finding(
            RawFinding(
                detector="regex.private_key",
                secret_type="private_key",
                file_path="docs/example-key.pem",
                raw_secret="-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----",
                confidence=0.98,
                source="test",
            )
        )

        decision = evaluate_findings([finding], CredHunterConfig())

        self.assertEqual(decision.action, "fail")
        self.assertEqual(decision.blocking_count, 1)
        self.assertEqual(decision.findings[0].risk_level, "critical")

    def test_docs_provider_token_is_warned_not_ignored(self):
        finding = normalize_finding(
            RawFinding(
                detector="regex.github_token",
                secret_type="github_token",
                file_path="docs/setup.md",
                raw_secret="ghp_1234567890abcdef1234567890",
                confidence=0.9,
                source="test",
            )
        )
        config = CredHunterConfig()
        config.scan.fail_on = "high"

        decision = evaluate_findings([finding], config)

        self.assertEqual(decision.action, "warn")
        self.assertEqual(decision.findings[0].risk_level, "medium")
        self.assertEqual(decision.findings[0].false_positive_assessment.classification, "uncertain")

    def test_local_database_url_is_ignored(self):
        finding = normalize_finding(
            RawFinding(
                detector="regex.database_url",
                secret_type="database_url",
                file_path=".env",
                raw_secret="mongodb://localhost:27017/app",
                confidence=0.82,
                source="test",
            )
        )

        assessment = assess_false_positive(finding, CredHunterConfig())
        decision = evaluate_findings([finding], CredHunterConfig())

        self.assertTrue(assessment.ignored)
        self.assertEqual(decision.ignored_count, 1)
        self.assertEqual(decision.action, "pass")

    def test_configured_ignore_path_is_ignored(self):
        finding = normalize_finding(
            RawFinding(
                detector="regex.github_token",
                secret_type="github_token",
                file_path="tests/fixtures/config.py",
                raw_secret="ghp_1234567890abcdef1234567890",
                confidence=0.9,
                source="test",
            )
        )
        config = CredHunterConfig()
        config.filters.ignore_paths = ["tests/fixtures/**"]

        decision = evaluate_findings([finding], config)

        self.assertEqual(decision.ignored_count, 1)
        self.assertEqual(decision.findings[0].action, "ignore")


if __name__ == "__main__":
    unittest.main()
