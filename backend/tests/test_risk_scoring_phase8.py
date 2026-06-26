import unittest

from app.ci.config import CredHunterConfig
from app.ci.decision import evaluate_findings
from app.scanner.models import RawFinding
from app.scanner.normalizer import normalize_finding
from app.services.false_positive_filter import assess_false_positive
from app.services.llm_filter_service import LLMClassification
from app.services.risk_scoring_service import score_finding
from app.services.validation_service import ValidationResult


class RiskScoringPhase8Tests(unittest.TestCase):
    def test_private_key_gets_critical_score(self):
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
        config = CredHunterConfig()
        assessment = assess_false_positive(finding, config)

        risk = score_finding(finding, config, assessment)

        self.assertEqual(risk.risk_level, "critical")
        self.assertGreaterEqual(risk.score, 90)

    def test_github_token_floor_reaches_critical_threshold(self):
        finding = _github_source_finding()
        config = CredHunterConfig()
        config.scan.fail_on = "critical"

        decision = evaluate_findings([finding], config)

        self.assertEqual(decision.action, "fail")
        self.assertEqual(decision.blocking_count, 1)
        self.assertEqual(decision.findings[0].risk_level, "critical")
        self.assertGreaterEqual(decision.findings[0].risk_score.score, 90)
        self.assertEqual(decision.findings[0].risk_score.risk_floor["provider"], "github_token")

    def test_active_validation_pushes_token_to_critical(self):
        finding = _github_source_finding()
        config = CredHunterConfig()
        validation = ValidationResult(
            provider="github",
            status="valid",
            active=True,
            reason="Token authenticated.",
            checked=True,
            network_used=True,
        )

        decision = evaluate_findings([finding], config, validation_results={finding.finding_id: validation})

        self.assertEqual(decision.action, "fail")
        self.assertEqual(decision.findings[0].risk_level, "critical")
        self.assertIn("validation", decision.findings[0].to_dict())

    def test_invalid_validation_lowers_database_url_risk(self):
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
        config = CredHunterConfig()
        validation = ValidationResult(
            provider="database_url",
            status="local_only",
            active=False,
            reason="Local database URL.",
            checked=True,
        )

        risk = score_finding(finding, config, assess_false_positive(finding, config), validation_result=validation)

        self.assertEqual(risk.risk_level, "low")

    def test_llm_false_positive_can_lower_ambiguous_doc_token(self):
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
        llm = LLMClassification(
            classification="likely_false_positive",
            confidence=0.91,
            reason="Documentation example.",
            recommended_action="ignore",
            model="o4-mini",
            used=True,
        )

        decision = evaluate_findings([finding], config, llm_classifications={finding.finding_id: llm})

        self.assertEqual(decision.action, "pass")
        self.assertEqual(decision.findings[0].action, "ignore")
        self.assertEqual(decision.findings[0].risk_score.risk_level, "low")

    def test_llm_true_positive_does_not_push_plain_generic_secret_above_medium(self):
        finding = normalize_finding(
            RawFinding(
                detector="gitleaks.generic",
                secret_type="generic_secret",
                file_path="src/settings.py",
                raw_secret="django-insecure-k8j2x9p0m5n1q4r7s3t6v8w2y5z0",
                confidence=1.0,
                source="test",
            )
        )
        config = CredHunterConfig()
        llm = LLMClassification(
            classification="true_positive",
            confidence=0.95,
            reason="Hardcoded generic application secret.",
            recommended_action="fail",
            model="o4-mini",
            used=True,
        )

        risk = score_finding(finding, config, assess_false_positive(finding, config), llm)

        self.assertEqual(risk.score, 59)
        self.assertEqual(risk.risk_level, "medium")
        self.assertEqual(risk.recommended_action, "warn")
        self.assertIn("generic_secret_cap", [component.name for component in risk.components])


def _github_source_finding():
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


if __name__ == "__main__":
    unittest.main()
