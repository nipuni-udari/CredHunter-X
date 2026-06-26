import json
import os
import unittest
from unittest.mock import patch

from app.ci.config import CredHunterConfig
from app.ci.decision import evaluate_findings
from app.scanner.models import RawFinding
from app.scanner.normalizer import normalize_finding
from app.services.llm_filter_service import LLMFilterService, build_llm_payload


class LLMPhase6Tests(unittest.TestCase):
    def test_llm_payload_does_not_include_raw_secret(self):
        raw_secret = "ghp_1234567890abcdef1234567890"
        finding = normalize_finding(
            RawFinding(
                detector="regex.github_token",
                secret_type="github_token",
                file_path="docs/setup.md",
                raw_secret=raw_secret,
                confidence=0.9,
                source="test",
            )
        )

        payload = build_llm_payload(finding, CredHunterConfig())

        self.assertNotIn(raw_secret, json.dumps(payload))
        self.assertIn("redacted_secret", payload)

    def test_llm_disabled_returns_skipped_assessment(self):
        finding = _github_docs_finding()
        config = CredHunterConfig()
        config.llm.enabled = False  # the pipeline is on by default; opt out here.
        service = LLMFilterService(config)

        assessment = service.classify_finding(finding)

        self.assertFalse(assessment.used)
        self.assertEqual(assessment.skipped_reason, "LLM filtering is disabled in configuration.")

    def test_llm_can_ignore_ambiguous_docs_finding(self):
        config = CredHunterConfig()
        config.llm.enabled = True
        config.llm.min_confidence = 0.8
        finding = _github_docs_finding()

        def fake_classifier(payload, active_config):
            return {
                "classification": "likely_false_positive",
                "confidence": 0.91,
                "reason": "Documentation example.",
                "recommended_action": "ignore",
            }

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            assessments = LLMFilterService(config, classifier=fake_classifier).classify_findings([finding], config)
            decision = evaluate_findings([finding], config, assessments)

        self.assertEqual(decision.action, "pass")
        self.assertEqual(decision.findings[0].action, "ignore")
        self.assertEqual(decision.findings[0].llm_classification.classification, "likely_false_positive")

    def test_classifier_schema_response_is_used(self):
        config = CredHunterConfig()
        config.llm.enabled = True
        finding = _github_docs_finding()

        def fake_classifier(payload, active_config):
            return {
                "classification": "not_false_positive",
                "confidence": 0.92,
                "reason": "A provider token appears in source context.",
            }

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            assessment = LLMFilterService(config, classifier=fake_classifier).classify_finding(finding)

        self.assertTrue(assessment.used)
        self.assertEqual(assessment.classification, "likely_true_positive")
        self.assertEqual(assessment.metadata["schema_classification"], "not_false_positive")

    def test_invalid_classifier_response_falls_back_safely(self):
        config = CredHunterConfig()
        config.llm.enabled = True
        finding = _github_docs_finding()

        def invalid(payload, active_config):
            return {"message": "not the schema"}

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            assessment = LLMFilterService(config, classifier=invalid).classify_finding(finding)

        self.assertFalse(assessment.used)
        self.assertTrue(assessment.metadata["fallback"])
        self.assertIn("expected schema", assessment.metadata["error"])

    def test_llm_true_positive_escalates_low_risk_finding(self):
        config = CredHunterConfig()
        config.llm.enabled = True
        config.llm.min_confidence = 0.8
        finding = normalize_finding(
            RawFinding(
                detector="entropy.assignment",
                secret_type="generic_high_entropy_secret",
                file_path="src/settings.py",
                raw_secret="xYz987654321ABCDEFGtokenvalue",
                confidence=0.55,
                source="test",
            )
        )

        def fake_classifier(payload, active_config):
            return {
                "classification": "likely_true_positive",
                "confidence": 0.88,
                "reason": "Production settings file with secret-like assignment.",
                "recommended_action": "warn",
            }

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            assessments = LLMFilterService(config, classifier=fake_classifier).classify_findings([finding], config)
            decision = evaluate_findings([finding], config, assessments)

        self.assertEqual(decision.findings[0].risk_level, "high")
        self.assertEqual(decision.action, "fail")

    def test_private_key_is_classified_but_not_downgraded(self):
        config = CredHunterConfig()
        config.llm.enabled = True
        finding = normalize_finding(
            RawFinding(
                detector="regex.private_key",
                secret_type="private_key",
                file_path="docs/key.pem",
                raw_secret="-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----",
                confidence=0.98,
                source="test",
            )
        )

        def fake_classifier(payload, active_config):
            return {
                "classification": "false_positive",
                "confidence": 0.99,
                "reason": "Model thinks this is a sample.",
                "recommended_action": "ignore",
            }

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            assessment = LLMFilterService(config, classifier=fake_classifier).classify_finding(finding)
            decision = evaluate_findings([finding], config, {finding.finding_id: assessment})

        self.assertTrue(assessment.used)
        self.assertEqual(assessment.classification, "false_positive")
        self.assertEqual(decision.findings[0].risk_level, "critical")
        self.assertEqual(decision.findings[0].action, "fail")


def _github_docs_finding():
    return normalize_finding(
        RawFinding(
            detector="regex.github_token",
            secret_type="github_token",
            file_path="docs/setup.md",
            raw_secret="ghp_1234567890abcdef1234567890",
            confidence=0.9,
            source="test",
        )
    )


if __name__ == "__main__":
    unittest.main()
