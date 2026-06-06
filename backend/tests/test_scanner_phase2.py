import json
import unittest
from pathlib import Path

from app.scanner.gitleaks_parser import parse_gitleaks_report
from app.scanner.redaction import hash_secret, redact_secret
from app.scanner.source_scanner import scan_path


class ScannerPhase2Tests(unittest.TestCase):
    def test_redact_secret_hides_middle(self):
        self.assertEqual(redact_secret("ghp_1234567890abcdef"), "ghp_****cdef")

    def test_hash_secret_is_stable(self):
        first = hash_secret("secret-value", key="test-key")
        second = hash_secret("secret-value", key="test-key")
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("hmac-sha256:"))

    def test_parse_gitleaks_json_does_not_expose_raw_secret(self):
        report_path = Path("tests/fixtures/gitleaks-report.json")
        findings = parse_gitleaks_report(report_path)

        self.assertEqual(len(findings), 1)
        finding = findings[0].to_dict()
        self.assertEqual(finding["detector"], "gitleaks")
        self.assertEqual(finding["secret_type"], "github_token")
        self.assertNotIn("ghp_1234567890abcdef1234567890", json.dumps(finding))
        self.assertEqual(finding["redacted_secret"], "ghp_****7890")

    def test_source_scanner_finds_database_url(self):
        findings = scan_path("tests/fixtures/sample-repo")

        self.assertGreaterEqual(len(findings), 1)
        self.assertTrue(any(finding.secret_type == "database_url" for finding in findings))


if __name__ == "__main__":
    unittest.main()
