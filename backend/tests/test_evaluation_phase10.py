import unittest

from app.ci.config import CredHunterConfig
from app.ci.decision import evaluate_findings
from app.evaluation.creddata_loader import load_balanced_creddata_sample
from app.evaluation.gitleaks_baseline import match_gitleaks_report_to_creddata
from app.evaluation.metrics import evaluate_decisions
from app.evaluation.phase10_runner import run_phase10_evaluation


class EvaluationPhase10Tests(unittest.TestCase):
    def test_balanced_sample_metrics_shape(self):
        records = load_balanced_creddata_sample(per_label=5)
        findings = [record.to_finding() for record in records]
        config = CredHunterConfig()
        config.scan.fail_on = "critical"

        decision = evaluate_findings(findings, config)
        metrics = evaluate_decisions(records, decision)

        self.assertEqual(metrics["record_count"], 10)
        self.assertEqual(metrics["label_counts"]["true_secret"], 5)
        self.assertEqual(metrics["label_counts"]["false_positive"], 5)
        self.assertIn("precision", metrics["baseline"])
        self.assertIn("recall", metrics["credhunter_x"])
        self.assertIn("false_positive_reduction", metrics["improvement"])

    def test_baseline_reports_all_candidates(self):
        result = run_phase10_evaluation(limit=20, balanced=True)
        baseline_matrix = result["metrics"]["baseline"]["confusion_matrix"]

        self.assertEqual(baseline_matrix["true_negative"], 0)
        self.assertEqual(baseline_matrix["false_negative"], 0)
        self.assertEqual(result["metrics"]["baseline"]["recall"], 1.0)

    def test_phase10_runner_full_small_sample(self):
        result = run_phase10_evaluation(limit=25)

        self.assertEqual(result["dataset"], "CredData Python Eval")
        self.assertEqual(result["metrics"]["record_count"], 25)
        self.assertGreater(result["runtime"]["records_per_second"], 0)
        self.assertIn("credhunter_x", result["metrics"])

    def test_gitleaks_report_baseline_matching(self):
        records = load_balanced_creddata_sample(per_label=2)

        matched = match_gitleaks_report_to_creddata("tests/fixtures/gitleaks-baseline-report.json", records)

        self.assertIn("creddata_py_029502", matched)

    def test_phase10_runner_accepts_gitleaks_baseline_report(self):
        result = run_phase10_evaluation(
            limit=10,
            balanced=True,
            gitleaks_report="tests/fixtures/gitleaks-baseline-report.json",
        )

        self.assertEqual(result["baseline_mode"], "gitleaks_report")
        self.assertEqual(result["gitleaks_matched_findings"], 1)


if __name__ == "__main__":
    unittest.main()
