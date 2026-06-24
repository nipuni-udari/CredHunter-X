import json
import os
import unittest
from pathlib import Path
from unittest import mock

from app.ci.backend_client import build_scan_payload
from app.ci.cli import main as ci_main
from app.ci.config import load_config
from app.ci.decision import evaluate_findings
from app.scanner.gitleaks_parser import parse_gitleaks_report


class CIPhase3Tests(unittest.TestCase):
    def test_load_yaml_config(self):
        config = load_config("tests/fixtures/credhunter.yml")

        self.assertEqual(config.scan.mode, "changed-files")
        self.assertEqual(config.scan.fail_on, "critical")
        self.assertEqual(config.filters.ignore_paths, ["docs/**", "tests/fixtures/**"])

    def test_evaluate_findings_requires_manual_review_below_critical_threshold(self):
        config = load_config("tests/fixtures/credhunter.yml")
        findings = parse_gitleaks_report("tests/fixtures/gitleaks-report.json")

        decision = evaluate_findings(findings, config)

        self.assertEqual(decision.action, "manual_review")
        self.assertEqual(decision.exit_code, 0)
        self.assertEqual(decision.manual_review_count, 1)

    def test_ci_cli_writes_reports_and_fails_on_high(self):
        output_dir = Path("tests/fixtures/generated")
        output_dir.mkdir(exist_ok=True)
        json_report = output_dir / "credhunter-report.json"
        sarif_report = output_dir / "credhunter-report.sarif"
        summary = output_dir / "summary.md"

        # Disable the LLM tier and any ambient key so the CLI stays offline.
        with mock.patch.dict(
            os.environ, {"CREDHUNTER_LLM_ENABLED": "false", "OPENAI_API_KEY": ""}
        ):
            exit_code = ci_main(
                [
                    "--gitleaks-report",
                    "tests/fixtures/gitleaks-report.json",
                    "--config",
                    "tests/fixtures/credhunter.yml",
                    "--fail-on",
                    "high",
                    "--no-python-extractor",
                    "--json-output",
                    str(json_report),
                    "--sarif-output",
                    str(sarif_report),
                    "--summary-output",
                    str(summary),
                ]
            )

        self.assertEqual(exit_code, 1)
        self.assertTrue(json_report.exists())
        self.assertTrue(sarif_report.exists())
        self.assertTrue(summary.exists())

        payload = json.loads(json_report.read_text(encoding="utf-8"))
        self.assertEqual(payload["action"], "fail")
        self.assertEqual(payload["blocking_count"], 1)
        self.assertIn("risk_score", payload["findings"][0])

    def test_ci_cli_runs_llm_when_enabled(self):
        from app.services.llm_filter_service import LLMClassification

        class FakeLLMService:
            def __init__(self, config):
                self.config = config

            def classify_findings(self, findings, config=None):
                return {
                    finding.finding_id: LLMClassification(
                        classification="likely_true_positive",
                        confidence=0.9,
                        reason="Looks like a real token in a source file.",
                        recommended_action="warn",
                        model="fake",
                        used=True,
                    )
                    for finding in findings
                }

        output_dir = Path("tests/fixtures/generated")
        output_dir.mkdir(exist_ok=True)
        json_report = output_dir / "credhunter-llm-report.json"
        sarif_report = output_dir / "credhunter-llm-report.sarif"

        # The classifier is mocked; the downstream ranker/explainer/remediation
        # stages are on by default, so clear any ambient key to keep them offline
        # (they skip gracefully and fall back to deterministic output).
        with mock.patch("app.ci.cli.LLMFilterService", FakeLLMService), mock.patch.dict(
            os.environ, {"OPENAI_API_KEY": ""}
        ):
            ci_main(
                [
                    "--gitleaks-report",
                    "tests/fixtures/gitleaks-report.json",
                    "--config",
                    "tests/fixtures/credhunter.yml",
                    "--enable-llm",
                    "--no-python-extractor",
                    "--json-output",
                    str(json_report),
                    "--sarif-output",
                    str(sarif_report),
                ]
            )

        payload = json.loads(json_report.read_text(encoding="utf-8"))
        self.assertIn("llm_filter", payload["findings"][0])
        self.assertEqual(
            payload["findings"][0]["llm_filter"]["classification"], "likely_true_positive"
        )

    def test_build_backend_scan_payload(self):
        config = load_config("tests/fixtures/credhunter.yml")
        findings = parse_gitleaks_report("tests/fixtures/gitleaks-report.json")

        # Isolate from CI environment variables (e.g. GITHUB_REPOSITORY) so the
        # payload falls back to deterministic local defaults.
        with mock.patch.dict(os.environ, {}, clear=True):
            payload = build_scan_payload(findings, config)

        self.assertEqual(payload["project_id"], "local/repository")
        self.assertEqual(payload["repository_id"], "local/repository")
        self.assertEqual(len(payload["findings"]), 1)
        self.assertNotIn("ghp_1234567890abcdef1234567890", json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
