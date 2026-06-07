import json
import unittest

from fastapi.testclient import TestClient

from app.api.app import create_app
from app.ci.config import CredHunterConfig
from app.evaluation.creddata_loader import (
    load_balanced_creddata_sample,
    load_creddata_records,
    load_creddata_summary,
    summarize_records,
)
from app.evaluation.phase9_runner import run_phase9_dataset_check
from app.services.llm_filter_service import build_llm_payload


class CredDataPhase9Tests(unittest.TestCase):
    def test_creddata_summary_matches_expected_shape(self):
        summary = load_creddata_summary()

        self.assertEqual(summary["records"], 4387)
        self.assertEqual(summary["labels"]["true_secret"], 654)
        self.assertEqual(summary["labels"]["false_positive"], 3733)

    def test_load_balanced_creddata_sample(self):
        records = load_balanced_creddata_sample(per_label=3)
        summary = summarize_records(records)

        self.assertEqual(summary["records"], 6)
        self.assertEqual(summary["labels"]["true_secret"], 3)
        self.assertEqual(summary["labels"]["false_positive"], 3)

    def test_creddata_record_converts_to_safe_finding(self):
        record = load_creddata_records(limit=1, labels={"true_secret"})[0]
        finding = record.to_finding()
        payload = finding.to_dict()

        self.assertEqual(payload["source"], "creddata")
        self.assertEqual(payload["metadata"]["ground_truth"], "true_secret")
        self.assertNotIn("raw_secret", json.dumps(payload))
        self.assertTrue(payload["secret_hash"].startswith("creddata-candidate:"))

    def test_llm_payload_does_not_leak_ground_truth_label(self):
        record = load_creddata_records(limit=1, labels={"true_secret"})[0]
        payload = build_llm_payload(record.to_finding(), config=CredHunterConfig())
        encoded = json.dumps(payload)

        self.assertNotIn("ground_truth", encoded)
        self.assertNotIn("true_secret", encoded)

    def test_backend_accepts_creddata_balanced_sample(self):
        client = TestClient(create_app())
        records = load_balanced_creddata_sample(per_label=2)
        findings = [record.to_finding().to_dict() for record in records]

        response = client.post(
            "/api/scans",
            json={
                "project_id": "creddata-phase9",
                "repository_id": "creddata-python-eval",
                "repository_name": "CredData Python Eval",
                "provider": "creddata",
                "findings": findings,
                "config": {"scan": {"fail_on": "critical"}},
            },
        )

        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.assertEqual(body["decision"]["finding_count"], 4)
        self.assertIn("manual_review_count", body["decision"])
        self.assertIn("risk_score", body["findings"][0])

    def test_phase9_runner_processes_creddata_sample(self):
        result = run_phase9_dataset_check(limit=10, balanced=True)

        self.assertEqual(result["dataset"], "CredData")
        self.assertEqual(result["record_summary"]["records"], 10)
        self.assertEqual(result["record_summary"]["labels"]["true_secret"], 5)
        self.assertEqual(result["record_summary"]["labels"]["false_positive"], 5)
        self.assertEqual(result["decision"]["finding_count"], 10)


if __name__ == "__main__":
    unittest.main()
