import json
import unittest
from pathlib import Path

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

    def test_evaluate_findings_warns_below_threshold(self):
        config = load_config("tests/fixtures/credhunter.yml")
        findings = parse_gitleaks_report("tests/fixtures/gitleaks-report.json")

        decision = evaluate_findings(findings, config)

        self.assertEqual(decision.action, "warn")
        self.assertEqual(decision.exit_code, 0)
        self.assertEqual(decision.warning_count, 1)

    def test_ci_cli_writes_reports_and_fails_on_high(self):
        output_dir = Path("tests/fixtures/generated")
        output_dir.mkdir(exist_ok=True)
        json_report = output_dir / "credhunter-report.json"
        sarif_report = output_dir / "credhunter-report.sarif"
        summary = output_dir / "summary.md"

        exit_code = ci_main(
            [
                "--gitleaks-report",
                "tests/fixtures/gitleaks-report.json",
                "--config",
                "tests/fixtures/credhunter.yml",
                "--fail-on",
                "high",
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


if __name__ == "__main__":
    unittest.main()
