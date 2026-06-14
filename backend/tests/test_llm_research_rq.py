"""Tests for the RQ2 (agentic workflow / ablation) and RQ3 (explanation quality) additions."""

import os
import unittest
from unittest.mock import patch

from app.ci.config import CredHunterConfig
from app.evaluation.creddata_loader import load_balanced_creddata_sample
from app.evaluation.explanation_quality import evaluate_explanations, score_explanation
from app.evaluation.llm_experiment import run_llm_ablation
from app.scanner.models import RawFinding
from app.scanner.normalizer import normalize_finding
from app.services.llm_filter_service import (
    LLMClassification,
    _openai_agentic_classifier,
    classifier_for_workflow,
)


def _finding(secret_type="generic_high_entropy_secret", file_path="src/settings.py"):
    return normalize_finding(
        RawFinding(
            detector="entropy.assignment",
            secret_type=secret_type,
            file_path=file_path,
            raw_secret="xYz987654321ABCDEFGtokenvalue",
            confidence=0.55,
            source="test",
        )
    )


class AgenticWorkflowTests(unittest.TestCase):
    def test_classifier_selection_by_workflow(self):
        self.assertEqual(classifier_for_workflow("single").__name__, "_openai_classifier")
        self.assertEqual(classifier_for_workflow("agentic").__name__, "_openai_agentic_classifier")
        self.assertEqual(classifier_for_workflow("unknown").__name__, "_openai_classifier")

    def test_agentic_classifier_runs_two_steps_and_records_revision(self):
        config = CredHunterConfig()
        step1 = {"classification": "uncertain", "confidence": 0.4}
        step2 = {
            "classification": "likely_false_positive",
            "confidence": 0.9,
            "reason": "On review the value is a documented example token.",
            "recommended_action": "ignore",
        }

        with patch(
            "app.services.llm_filter_service._openai_json_call",
            side_effect=[step1, step2],
        ) as mock_call:
            result = _openai_agentic_classifier({"secret_type": "generic_secret"}, config)

        self.assertEqual(mock_call.call_count, 2)
        self.assertEqual(result["classification"], "likely_false_positive")
        self.assertEqual(result["metadata"]["workflow"], "agentic")
        self.assertEqual(result["metadata"]["preliminary_classification"], "uncertain")
        self.assertTrue(result["metadata"]["label_revised"])


class AblationRunnerTests(unittest.TestCase):
    def _fake(self, classification, reason, action, revised=False):
        def classifier(payload, config):
            return {
                "classification": classification,
                "confidence": 0.9,
                "reason": reason,
                "recommended_action": action,
                "metadata": {"label_revised": revised},
            }

        return classifier

    def test_ablation_reports_each_arm_and_agreement(self):
        records = load_balanced_creddata_sample(per_label=8)
        classifiers = {
            "llm_single": self._fake("likely_false_positive", "Single-prompt verdict.", "ignore"),
            "llm_agentic": self._fake("uncertain", "Agentic verdict after review.", "manual_review", revised=True),
        }

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            result = run_llm_ablation(records, classifiers=classifiers)

        for arm in ("rules_only", "llm_single", "llm_agentic"):
            self.assertIn(arm, result["arms"])
            self.assertIn("precision", result["arms"][arm]["credhunter_x"])

        self.assertIn("per_arm", result["comparison"])
        self.assertIn("single_vs_agentic_agreement", result["comparison"])
        self.assertIn("workflow_stats", result["arms"]["llm_agentic"])
        # Agentic fake always revises, so revision rate should be > 0 when it ran.
        stats = result["arms"]["llm_agentic"]["workflow_stats"]
        if stats["classified_by_llm"]:
            self.assertGreater(stats["label_revision_rate"], 0.0)


class ExplanationQualityTests(unittest.TestCase):
    def test_good_explanation_scores_high(self):
        finding = _finding()
        classification = LLMClassification(
            classification="likely_false_positive",
            confidence=0.9,
            reason="The value sits in a test fixture and matches a placeholder example, not a live secret.",
            recommended_action="ignore",
            model="o4-mini",
            used=True,
        )

        score = score_explanation(finding, classification, ground_truth="false_positive")

        self.assertTrue(score.checks["schema_valid"])
        self.assertTrue(score.checks["action_consistent"])
        self.assertTrue(score.checks["references_context"])
        self.assertTrue(score.checks["label_correct"])
        self.assertGreaterEqual(score.score, 0.8)

    def test_inconsistent_action_and_wrong_label_are_flagged(self):
        finding = _finding()
        classification = LLMClassification(
            classification="false_positive",
            confidence=0.9,
            reason="bad",  # trivial
            recommended_action="block",  # inconsistent with false_positive
            model="o4-mini",
            used=True,
        )

        score = score_explanation(finding, classification, ground_truth="true_secret")

        self.assertFalse(score.checks["action_consistent"])
        self.assertFalse(score.checks["non_trivial"])
        self.assertFalse(score.checks["label_correct"])
        self.assertLess(score.score, 0.6)

    def test_private_key_body_in_reason_is_secret_leak(self):
        finding = _finding(secret_type="private_key")
        classification = LLMClassification(
            classification="true_positive",
            confidence=0.95,
            reason="This contains -----BEGIN PRIVATE KEY----- material and must be rotated.",
            recommended_action="block",
            model="o4-mini",
            used=True,
        )

        score = score_explanation(finding, classification, ground_truth="true_secret")

        self.assertFalse(score.checks["no_secret_leak"])

    def test_evaluate_explanations_aggregates_and_uses_judge(self):
        finding = _finding()
        classification = LLMClassification(
            classification="likely_false_positive",
            confidence=0.9,
            reason="Placeholder example token in documentation, not a real credential.",
            recommended_action="ignore",
            model="o4-mini",
            used=True,
        )
        skipped = LLMClassification(
            classification="uncertain", confidence=0.0, reason="", recommended_action="keep_rule_decision",
            model="o4-mini", used=False,
        )

        def judge(f, c):
            return {"score": 0.75, "rationale": "Clear and actionable."}

        summary = evaluate_explanations(
            [(finding, classification, "false_positive"), (finding, skipped, "false_positive")],
            judge=judge,
        )

        self.assertEqual(summary["explanations_scored"], 1)
        self.assertEqual(summary["explanations_skipped"], 1)
        self.assertIn("schema_valid", summary["check_pass_rate"])
        self.assertEqual(summary["mean_judge_score"], 0.75)


if __name__ == "__main__":
    unittest.main()
