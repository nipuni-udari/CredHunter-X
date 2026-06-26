"""Tests for the downstream LLM pipeline stages: Ranker, Explainer, Remediation.

These mirror the phase-6 classifier tests: the OpenAI call is replaced with an
injected deterministic callable, so the tests exercise the real service/decision
wiring without network access.
"""

import os
import unittest
from unittest.mock import patch

from app.ci.config import CredHunterConfig
from app.ci.decision import evaluate_findings
from app.reporting.markdown import build_pr_comment
from app.scanner.models import RawFinding
from app.scanner.normalizer import normalize_finding
from app.services.llm_explainer_service import LLMExplainerService
from app.services.llm_ranker_service import LLMRankerService
from app.services.llm_remediation_service import LLMRemediationService


def _finding(secret_type="generic_high_entropy_secret", file_path="src/settings.py", confidence=0.55):
    return normalize_finding(
        RawFinding(
            detector="entropy.assignment",
            secret_type=secret_type,
            file_path=file_path,
            raw_secret="xYz987654321ABCDEFGtokenvalue",
            confidence=confidence,
            source="test",
        )
    )


def _pipeline_config():
    config = CredHunterConfig()
    config.llm.enabled = True
    config.llm.rank = True
    config.llm.explain = True
    config.llm.remediate = True
    return config


class LLMRankerTests(unittest.TestCase):
    def test_disabled_ranker_retains_deterministic_score(self):
        config = CredHunterConfig()
        config.llm.rank = False  # pipeline is on by default; opt this stage out.
        ranking = LLMRankerService(config).rank_finding(_finding())

        self.assertFalse(ranking.used)
        self.assertEqual(ranking.skipped_reason, "LLM ranking is disabled in configuration.")

    def test_ranker_score_overrides_decision(self):
        config = _pipeline_config()
        finding = _finding()

        def fake_ranker(payload, active_config):
            return {"score": 85, "rationale": "Live-looking token in a settings module."}

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            rankings = LLMRankerService(config, ranker=fake_ranker).rank_findings([finding], {}, config)
            decision = evaluate_findings([finding], config, llm_rankings=rankings)

        item = decision.findings[0]
        self.assertTrue(rankings[finding.finding_id].used)
        self.assertEqual(item.risk_score.score, 85)
        self.assertEqual(item.risk_score.source, "llm")
        self.assertEqual(item.risk_level, "critical")
        self.assertEqual(decision.action, "fail")

    def test_ranker_schema_response_is_used(self):
        config = _pipeline_config()
        finding = _finding()

        def fake_ranker(payload, active_config):
            return {
                "risk_score": 77,
                "severity": "high",
                "reason": "Hardcoded token in application settings.",
            }

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            ranking = LLMRankerService(config, ranker=fake_ranker).rank_finding(finding, None, config)

        self.assertTrue(ranking.used)
        self.assertEqual(ranking.score, 77)
        self.assertEqual(ranking.risk_level, "high")

    def test_ranker_normalizes_mismatched_model_severity_to_score_band(self):
        config = _pipeline_config()
        medium_finding = _finding(secret_type="generic_secret")
        critical_finding = _finding(secret_type="generic_secret", file_path="src/other_settings.py")

        def medium_ranker(payload, active_config):
            return {
                "risk_score": 45,
                "severity": "high",
                "reason": "Model severity does not match the numeric score.",
            }

        def critical_ranker(payload, active_config):
            return {
                "risk_score": 85,
                "severity": "high",
                "reason": "Model severity does not match the numeric score.",
            }

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            medium = LLMRankerService(config, ranker=medium_ranker).rank_finding(
                medium_finding, None, config
            )
            critical = LLMRankerService(config, ranker=critical_ranker).rank_finding(
                critical_finding, None, config
            )

        self.assertEqual(medium.score, 45)
        self.assertEqual(medium.risk_level, "medium")
        self.assertEqual(medium.recommended_action, "warn")
        self.assertEqual(medium.metadata["model_severity"], "high")
        self.assertEqual(medium.metadata["severity_normalized"], "medium")
        self.assertEqual(critical.score, 85)
        self.assertEqual(critical.risk_level, "critical")
        self.assertEqual(critical.recommended_action, "fail")
        self.assertEqual(critical.metadata["model_severity"], "high")
        self.assertEqual(critical.metadata["severity_normalized"], "critical")

    def test_ranker_cannot_lower_private_key_below_floor(self):
        config = _pipeline_config()
        finding = _finding(secret_type="private_key", file_path="deploy/key.pem")

        def fake_ranker(payload, active_config):
            return {"score": 5, "rationale": "Looks like a sample."}

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            ranking = LLMRankerService(config, ranker=fake_ranker).rank_finding(finding, None, config)

        self.assertTrue(ranking.used)
        self.assertGreaterEqual(ranking.score, 90)
        self.assertEqual(ranking.risk_level, "critical")

    def test_ranker_falls_back_on_error(self):
        config = _pipeline_config()
        finding = _finding()

        def boom(payload, active_config):
            raise RuntimeError("api down")

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            ranking = LLMRankerService(config, ranker=boom).rank_finding(finding, None, config)

        self.assertFalse(ranking.used)
        self.assertEqual(ranking.skipped_reason, "api down")
        self.assertTrue(ranking.metadata["fallback"])
        self.assertEqual(ranking.metadata["error"], "api down")


class LLMExplainerTests(unittest.TestCase):
    def test_explanation_is_surfaced_on_decision(self):
        config = _pipeline_config()
        finding = _finding(secret_type="aws_access_key", file_path="src/app.py", confidence=0.9)

        def fake_explainer(payload, active_config):
            return {"explanation": "An AWS access key appears hardcoded in application source."}

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            explanations = LLMExplainerService(config, explainer=fake_explainer).explain_findings(
                [finding], {}, {}, config
            )
            decision = evaluate_findings([finding], config, llm_explanations=explanations)

        item = decision.findings[0]
        self.assertTrue(item.llm_explanation.used)
        self.assertIn("AWS access key", item.explanation())
        self.assertIn("AWS access key", item.to_dict()["llm_explanation"]["explanation"])

    def test_disabled_explainer_falls_back_to_reason(self):
        config = CredHunterConfig()
        config.llm.explain = False  # pipeline is on by default; opt this stage out.
        explanation = LLMExplainerService(config).explain_finding(_finding())

        self.assertFalse(explanation.used)
        self.assertEqual(explanation.skipped_reason, "LLM explanation is disabled in configuration.")

    def test_empty_explanation_is_marked_unused(self):
        config = _pipeline_config()

        def empty(payload, active_config):
            return {"explanation": "   "}

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            explanation = LLMExplainerService(config, explainer=empty).explain_finding(_finding())

        self.assertFalse(explanation.used)


class LLMRemediationTests(unittest.TestCase):
    def test_llm_steps_replace_template(self):
        config = _pipeline_config()
        finding = _finding(secret_type="github_token", file_path="src/app.py", confidence=0.9)

        def fake_remediator(payload, active_config):
            return {"steps": ["Revoke this specific GitHub token", "Purge it from git history"]}

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            remediations = LLMRemediationService(config, remediator=fake_remediator).remediate_findings(
                [finding], {}, {}, config
            )
            decision = evaluate_findings([finding], config, llm_remediations=remediations)

        item = decision.findings[0]
        self.assertTrue(item.llm_remediation.used)
        self.assertEqual(item.remediation()[0], "Revoke this specific GitHub token")
        self.assertEqual(item.to_dict()["remediation"][0], "Revoke this specific GitHub token")

    def test_remediation_schema_response_is_used(self):
        config = _pipeline_config()
        finding = _finding(secret_type="github_token", file_path="src/app.py", confidence=0.9)

        def fake_remediator(payload, active_config):
            return {
                "remediation_steps": ["Revoke the GitHub token", "Move the replacement to GitHub Actions Secrets"],
                "safe_code_pattern": 'GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")',
            }

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            remediation = LLMRemediationService(config, remediator=fake_remediator).remediate_finding(
                finding, None, None, config
            )

        self.assertTrue(remediation.used)
        self.assertEqual(remediation.steps[0], "Revoke the GitHub token")
        self.assertIn("safe_code_pattern", remediation.metadata)

    def test_disabled_remediation_uses_template(self):
        config = CredHunterConfig()
        config.llm.remediate = False  # pipeline is on by default; opt this stage out.
        finding = _finding(secret_type="github_token")
        remediation = LLMRemediationService(config).remediate_finding(finding)

        self.assertFalse(remediation.used)
        self.assertEqual(remediation.skipped_reason, "LLM remediation is disabled in configuration.")
        # Falls back to the static per-type template.
        self.assertTrue(any("token" in step.lower() for step in remediation.steps))

    def test_no_usable_steps_falls_back_to_template(self):
        config = _pipeline_config()
        finding = _finding(secret_type="github_token")

        def empty(payload, active_config):
            return {"steps": ["", "   "]}

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            remediation = LLMRemediationService(config, remediator=empty).remediate_finding(finding, None, None, config)

        self.assertFalse(remediation.used)
        self.assertTrue(remediation.steps)  # template fallback


class LLMPipelineEndToEndTests(unittest.TestCase):
    def test_full_pipeline_surfaces_in_pr_comment(self):
        config = _pipeline_config()
        finding = _finding(secret_type="aws_access_key", file_path="src/app.py", confidence=0.9)

        rank = lambda payload, c: {"score": 88, "rationale": "Active-looking AWS key in source."}
        explain = lambda payload, c: {"explanation": "Hardcoded AWS access key in application source code."}
        remediate = lambda payload, c: {"steps": ["Disable the AWS key in IAM", "Rotate and store in a secret manager"]}

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            classifications = {}
            rankings = LLMRankerService(config, ranker=rank).rank_findings([finding], classifications, config)
            explanations = LLMExplainerService(config, explainer=explain).explain_findings(
                [finding], classifications, rankings, config
            )
            remediations = LLMRemediationService(config, remediator=remediate).remediate_findings(
                [finding], classifications, rankings, config
            )
            decision = evaluate_findings(
                [finding],
                config,
                llm_rankings=rankings,
                llm_explanations=explanations,
                llm_remediations=remediations,
            )

        comment = build_pr_comment(decision)
        self.assertEqual(decision.action, "fail")
        self.assertIn("Hardcoded AWS access key", comment)
        self.assertIn("Disable the AWS key in IAM", comment)


if __name__ == "__main__":
    unittest.main()
