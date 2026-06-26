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

    def test_docs_provider_token_is_not_ignored_or_downgraded_below_floor(self):
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

        self.assertEqual(decision.action, "fail")
        self.assertEqual(decision.findings[0].risk_level, "critical")
        self.assertGreaterEqual(decision.findings[0].risk_score.score, 90)
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


class FalsePositiveStrengthenedRulesTests(unittest.TestCase):
    def _assess(self, **kwargs):
        finding = normalize_finding(RawFinding(source="test", **kwargs))
        return finding, assess_false_positive(finding, CredHunterConfig())

    def test_hash_like_generic_value_is_ignored(self):
        _, assessment = self._assess(
            detector="regex.generic",
            secret_type="generic_secret",
            file_path="src/util.py",
            raw_secret="d41d8cd98f00b204e9800998ecf8427e",  # md5-shaped hex
        )
        self.assertTrue(assessment.ignored)
        self.assertTrue(assessment.signals["hash_like"])

    def test_uuid_generic_value_is_ignored(self):
        _, assessment = self._assess(
            detector="regex.generic",
            secret_type="generic_secret",
            file_path="src/util.py",
            raw_secret="123e4567-e89b-12d3-a456-426614174000",
        )
        self.assertTrue(assessment.ignored)
        self.assertTrue(assessment.signals["uuid_like"])

    def test_sequential_value_is_ignored(self):
        _, assessment = self._assess(
            detector="regex.generic",
            secret_type="generic_secret",
            file_path="src/config.py",
            raw_secret="abcdefghijkl",
        )
        self.assertTrue(assessment.ignored)
        self.assertTrue(assessment.signals["repeated_or_low_value"])

    def test_low_entropy_generic_value_is_ignored(self):
        _, assessment = self._assess(
            detector="regex.generic",
            secret_type="generic_secret",
            file_path="src/config.py",
            raw_secret="aaaaaabbbbbb",
            entropy=1.0,
        )
        self.assertTrue(assessment.ignored)
        self.assertTrue(assessment.signals["low_entropy_value"])

    def test_no_extractable_value_is_ignored(self):
        _, assessment = self._assess(
            detector="regex.generic",
            secret_type="generic_secret",
            file_path="src/app.py",
            raw_secret=None,
        )
        self.assertTrue(assessment.ignored)
        self.assertTrue(assessment.signals["no_secret_value"])

    def test_low_entropy_does_not_downgrade_typed_provider(self):
        # A provider token can be low-entropy by format; never downgrade it here.
        _, assessment = self._assess(
            detector="regex.github_token",
            secret_type="github_token",
            file_path="src/config.py",
            raw_secret="ghp_aaaaaaaaaaaaaaaaaaaa",
            entropy=1.0,
        )
        self.assertFalse(assessment.ignored)
        self.assertEqual(assessment.classification, "not_false_positive")

    def test_low_entropy_does_not_downgrade_private_key(self):
        _, assessment = self._assess(
            detector="regex.private_key",
            secret_type="private_key",
            file_path="src/key.pem",
            raw_secret="-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
            entropy=1.0,
        )
        self.assertFalse(assessment.ignored)
        self.assertEqual(assessment.classification, "not_false_positive")

    def test_real_high_entropy_secret_in_source_is_preserved(self):
        _, assessment = self._assess(
            detector="regex.generic",
            secret_type="generic_secret",
            file_path="src/config.py",
            raw_secret="Zx9Qw3Lk7Pm2Vt8Rn5Bc1Yd6",
            entropy=4.4,
        )
        self.assertFalse(assessment.ignored)
        self.assertEqual(assessment.classification, "not_false_positive")


if __name__ == "__main__":
    unittest.main()
