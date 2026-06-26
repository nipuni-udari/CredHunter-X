"""Tests for the phase-15 pipeline additions:

context enrichment, the Python AST extractor, candidate merge/dedupe, the LLM
response cache, the new local-filter rules (env refs / test values / redacted),
the cost-aware LLM gating, and the developer Markdown report.
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from app.ci.cli import _cost_aware_targets
from app.ci.config import CredHunterConfig
from app.ci.decision import FindingDecision, evaluate_findings
from app.reporting.markdown import build_markdown_summary, build_pr_comment
from app.reporting.html_report import build_html_report
from app.ci.decision import CIDecision
from app.scanner.candidate_merger import merge_and_dedupe
from app.scanner.models import NormalizedFinding, RawFinding
from app.scanner.normalizer import normalize_finding
from app.scanner.python_candidate_extractor import extract_python_candidates
from app.scanner.source_context import enrich_with_source_context, mask_line
from app.services import llm_cache
from app.services.false_positive_filter import assess_false_positive
from app.services.llm_client import call_llm_json, parse_json_response
from app.services.llm_explainer_service import LLMExplanation
from app.services.llm_explainer_service import LLMExplainerService
from app.services.llm_filter_service import LLMClassification
from app.services.llm_filter_service import LLMFilterService
from app.services.llm_ranker_service import LLMRanking
from app.services.llm_ranker_service import LLMRankerService
from app.services.llm_remediation_service import LLMRemediation
from app.services.llm_remediation_service import LLMRemediationService
from app.services.risk_scoring_service import RiskScore


def _finding(**overrides) -> NormalizedFinding:
    raw = RawFinding(
        detector=overrides.pop("detector", "gitleaks"),
        secret_type=overrides.pop("secret_type", "generic_secret"),
        file_path=overrides.pop("file_path", "src/config.py"),
        line_number=overrides.pop("line_number", 1),
        raw_secret=overrides.pop("raw_secret", "realsecretvalue1234567890"),
        source=overrides.pop("source", "gitleaks_json"),
        **overrides,
    )
    return normalize_finding(raw)


class MaskLineTests(unittest.TestCase):
    def test_masks_quoted_secret_but_keeps_env_var_name(self):
        masked = mask_line('API_KEY = "sk_live_abcdefghijklmnopqrstuv"')
        self.assertNotIn("abcdefghijklmnop", masked)
        self.assertIn("****", masked)

    def test_env_reference_line_is_unchanged_in_substance(self):
        masked = mask_line('API_KEY = os.getenv("API_KEY")')
        self.assertIn("os.getenv", masked)
        self.assertIn("API_KEY", masked)


class SourceContextTests(unittest.TestCase):
    def test_enrichment_attaches_masked_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "config.py"
            target.write_text(
                "import os\n"
                "client = Client()\n"
                'API_KEY = "sk_live_abcdefghijklmnopqrstuv"\n'
                "client.use(API_KEY)\n",
                encoding="utf-8",
            )
            finding = _finding(file_path="config.py", line_number=3)
            enrich_with_source_context([finding], tmp, before=2, after=1)

            self.assertIn("import os", finding.context_before)
            self.assertIn("client.use", finding.context_after)
            self.assertEqual(finding.metadata["signals"]["env_reference"], False)
            self.assertNotIn("abcdefghijklmnop", finding.metadata["target_line"])

    def test_env_reference_signal_is_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "settings.py"
            target.write_text('TOKEN = os.getenv("TOKEN")\n', encoding="utf-8")
            finding = _finding(file_path="settings.py", line_number=1)
            enrich_with_source_context([finding], tmp)
            self.assertTrue(finding.metadata["signals"]["env_reference"])

    def test_neighbour_secret_is_masked_in_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "config.py"
            target.write_text(
                'API_KEY = "sk_live_abcdefghijklmnopqrstuv"\n'
                "value = 1\n"
                'OTHER = "anotherlongsecretvalue12345"\n',
                encoding="utf-8",
            )
            finding = _finding(file_path="config.py", line_number=2)
            enrich_with_source_context([finding], tmp, before=1, after=1)
            self.assertNotIn("sk_live_abcdefghijklmnopqrstuv", finding.context_before)
            self.assertNotIn("anotherlongsecretvalue12345", finding.context_after)

    def test_missing_file_is_tolerated(self):
        finding = _finding(file_path="does/not/exist.py", line_number=10)
        # Should not raise and should leave context untouched.
        enrich_with_source_context([finding], ".")
        self.assertIsNone(finding.context_before)


class PythonExtractorTests(unittest.TestCase):
    def _extract(self, source: str):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "module.py"
            path.write_text(source, encoding="utf-8")
            return extract_python_candidates(tmp)

    def test_finds_hardcoded_assignment(self):
        findings = self._extract('API_KEY = "sk_live_abcdefghijklmnop1234"\n')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].source, "python_extractor")
        self.assertEqual(findings[0].metadata["candidate_type"], "api_key_assignment")

    def test_skips_env_reference(self):
        findings = self._extract('API_KEY = os.getenv("API_KEY")\n')
        self.assertEqual(findings, [])

    def test_finds_dict_key_credential(self):
        findings = self._extract(
            'headers = {"Authorization": "Bearer abcdefghijklmnop1234"}\n'
        )
        self.assertTrue(findings)
        types = {f.metadata.get("candidate_type") for f in findings}
        self.assertTrue({"authorization_header"} & types)

    def test_finds_connection_string_with_credentials(self):
        findings = self._extract(
            'DB = "postgres://user:supersecret@db.example.com:5432/app"\n'
        )
        self.assertTrue(any(f.secret_type == "database_url" for f in findings))

    def test_ignores_short_values(self):
        findings = self._extract('password = "short"\n')
        self.assertEqual(findings, [])

    def test_does_not_expose_raw_secret(self):
        findings = self._extract('token = "supersecretvalue1234567"\n')
        self.assertTrue(findings)
        self.assertNotIn("supersecretvalue1234567", findings[0].redacted_secret or "")


class CandidateMergerTests(unittest.TestCase):
    def test_dedupes_same_location_and_prefers_gitleaks(self):
        gitleaks = _finding(
            file_path="src/config.py",
            line_number=12,
            raw_secret="ghp_aaaaaaaaaaaaaaaaaaaa",
            secret_type="github_token",
            source="gitleaks_json",
            detector="gitleaks",
            rule_id="github-token",
        )
        python = _finding(
            file_path="src/config.py",
            line_number=12,
            raw_secret="ghp_aaaaaaaaaaaaaaaaaaaa",
            secret_type="generic_secret",
            source="python_extractor",
            detector="python.ast",
            rule_id="python-generic-secret",
            confidence=0.9,
        )
        merged = merge_and_dedupe([gitleaks], [python])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].source, "gitleaks_json")
        self.assertEqual(merged[0].confidence, 0.9)
        self.assertIn("gitleaks", merged[0].metadata.get("detected_by", []))
        self.assertIn("python.ast", merged[0].metadata.get("detected_by", []))
        self.assertIn("gitleaks_json", merged[0].metadata.get("detected_sources", []))
        self.assertIn("python_extractor", merged[0].metadata.get("detected_sources", []))
        self.assertIn("github_token", merged[0].metadata.get("merged_secret_types", []))
        self.assertIn("generic_secret", merged[0].metadata.get("merged_secret_types", []))
        self.assertIn("github-token", merged[0].metadata.get("merged_rule_ids", []))
        self.assertIn("python-generic-secret", merged[0].metadata.get("merged_rule_ids", []))

    def test_keeps_distinct_findings(self):
        a = _finding(file_path="a.py", line_number=1, raw_secret="aaaaaaaaaaaaaaaaaaaa")
        b = _finding(file_path="b.py", line_number=2, raw_secret="bbbbbbbbbbbbbbbbbbbb")
        merged = merge_and_dedupe([a], [b])
        self.assertEqual(len(merged), 2)


class LLMCacheTests(unittest.TestCase):
    def test_round_trip_and_key_stability(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"CREDHUNTER_CACHE_DIR": tmp, "CREDHUNTER_LLM_CACHE": "true"}):
                payload = {"file_path": "a.py", "line_number": 5, "secret_type": "generic_secret"}
                key = llm_cache.make_key("o4-mini", "classify", payload)
                self.assertEqual(key, llm_cache.make_key("o4-mini", "classify", payload))
                self.assertIsNone(llm_cache.get(key))
                llm_cache.save(key, {"classification": "true_positive"})
                self.assertEqual(llm_cache.get(key), {"classification": "true_positive"})

    def test_disabled_cache_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"CREDHUNTER_CACHE_DIR": tmp, "CREDHUNTER_LLM_CACHE": "false"}):
                key = llm_cache.make_key("o4-mini", "classify", {"x": 1})
                llm_cache.save(key, {"classification": "true_positive"})
                self.assertIsNone(llm_cache.get(key))


class LLMCacheIntegrationTests(unittest.TestCase):
    def test_second_identical_call_is_served_from_cache(self):
        from app.services import llm_client

        calls = {"count": 0}

        class _Resp:
            output_text = '{"classification": "true_positive"}'

        class _FakeClient:
            def __init__(self, *a, **k):
                self.responses = self

            def create(self, **kwargs):
                calls["count"] += 1
                return _Resp()

        fake_openai = mock.MagicMock()
        fake_openai.OpenAI = _FakeClient

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(
                os.environ,
                {"CREDHUNTER_CACHE_DIR": tmp, "CREDHUNTER_LLM_CACHE": "true", "OPENAI_API_KEY": "x"},
            ), mock.patch.dict("sys.modules", {"openai": fake_openai}):
                config = CredHunterConfig()
                payload = {"file_path": "a.py", "line_number": 1}
                first = llm_client.openai_json_call(config, "classify", payload, 100)
                second = llm_client.openai_json_call(config, "classify", payload, 100)

        self.assertEqual(first, {"classification": "true_positive"})
        self.assertEqual(second, first)
        self.assertEqual(calls["count"], 1)  # second call served from cache.


class StructuredOutputClientTests(unittest.TestCase):
    def test_call_llm_json_uses_strict_json_schema(self):
        calls = []

        class _Resp:
            output_text = '{"classification": "not_false_positive", "confidence": 0.93, "reason": "provider token"}'

        class _FakeResponses:
            def create(self, **kwargs):
                calls.append(kwargs)
                return _Resp()

        class _FakeClient:
            def __init__(self, *a, **k):
                self.responses = _FakeResponses()

        fake_openai = mock.MagicMock()
        fake_openai.OpenAI = _FakeClient
        schema = {
            "type": "object",
            "properties": {
                "classification": {"type": "string", "enum": ["not_false_positive", "false_positive", "unknown"]},
                "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                "reason": {"type": "string"},
            },
            "required": ["classification", "confidence", "reason"],
            "additionalProperties": False,
        }

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(
                os.environ,
                {"CREDHUNTER_CACHE_DIR": tmp, "CREDHUNTER_LLM_CACHE": "false", "OPENAI_API_KEY": "x"},
            ), mock.patch.dict("sys.modules", {"openai": fake_openai}):
                result = call_llm_json(
                    "gpt-4o-mini",
                    "classify",
                    '{"secret_type": "github_token"}',
                    "credhunter_classifier",
                    schema,
                )

        self.assertEqual(result["classification"], "not_false_positive")
        request = calls[0]
        self.assertEqual(request["model"], "gpt-4o-mini")
        self.assertEqual(request["text"]["format"]["type"], "json_schema")
        self.assertEqual(request["text"]["format"]["name"], "credhunter_classifier")
        self.assertTrue(request["text"]["format"]["strict"])
        self.assertFalse(request["text"]["format"]["schema"]["additionalProperties"])


class LLMJsonParsingTests(unittest.TestCase):
    def test_parses_plain_json(self):
        parsed = parse_json_response('{"classification": "true_positive"}')
        self.assertEqual(parsed, {"classification": "true_positive"})

    def test_parses_fenced_json(self):
        parsed = parse_json_response('```json\n{"classification": "false_positive"}\n```')
        self.assertEqual(parsed["classification"], "false_positive")

    def test_extracts_json_with_surrounding_text(self):
        parsed = parse_json_response('Here is the result:\n{"score": 82, "rationale": "high risk"}\nDone.')
        self.assertEqual(parsed["score"], 82)


class LocalFilterTests(unittest.TestCase):
    def setUp(self):
        self.config = CredHunterConfig()

    def test_env_reference_is_ignored(self):
        finding = _finding(secret_type="generic_secret")
        finding.metadata.setdefault("signals", {})["env_reference"] = True
        assessment = assess_false_positive(finding, self.config)
        self.assertTrue(assessment.ignored)
        self.assertEqual(assessment.classification, "false_positive")

    def test_test_value_is_ignored(self):
        finding = _finding(raw_secret="fake-key-test123-value")
        assessment = assess_false_positive(finding, self.config)
        self.assertTrue(assessment.ignored)

    def test_raw_placeholder_value_is_ignored(self):
        finding = _finding(secret_type="stripe_api_key", raw_secret="YOUR_API_KEY_HERE")
        finding.metadata["target_line"] = 'STRIPE_API_KEY = "YOUR_API_KEY_HERE"'
        assessment = assess_false_positive(finding, self.config)
        self.assertTrue(assessment.ignored)
        self.assertEqual(assessment.classification, "false_positive")

    def test_masked_placeholder_value_is_ignored(self):
        finding = _finding(secret_type="stripe_api_key", raw_secret="YOUR****HERE")
        finding.metadata["target_line"] = 'STRIPE_API_KEY = "YOUR****HERE"'
        assessment = assess_false_positive(finding, self.config)
        self.assertTrue(assessment.ignored)
        self.assertEqual(assessment.classification, "false_positive")

    def test_short_test_password_is_ignored(self):
        finding = _finding(secret_type="generic_secret", raw_secret="test123")
        finding.metadata["target_line"] = 'TEST_PASSWORD = "test123"'
        assessment = assess_false_positive(finding, self.config)
        self.assertTrue(assessment.ignored)

    def test_private_key_is_never_ignored_by_env_signal(self):
        finding = _finding(secret_type="private_key", raw_secret="-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----")
        finding.metadata.setdefault("signals", {})["env_reference"] = True
        assessment = assess_false_positive(finding, self.config)
        self.assertFalse(assessment.ignored)


class CostAwareTargetTests(unittest.TestCase):
    def setUp(self):
        self.config = CredHunterConfig()

    def test_excludes_rule_ignored_and_llm_false_positives(self):
        real = _finding(file_path="a.py", line_number=1, raw_secret="realsecretvalue1234567")
        env_ref = _finding(file_path="b.py", line_number=2, raw_secret="realsecretvalue7654321")
        env_ref.metadata.setdefault("signals", {})["env_reference"] = True
        llm_fp = _finding(file_path="c.py", line_number=3, raw_secret="anotherrealvalue9999")
        pk = _finding(secret_type="private_key", file_path="d.py", line_number=4, raw_secret="-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----")

        classifications = {
            real.finding_id: LLMClassification("likely_true_positive", 0.9, "", "warn", "m", True),
            llm_fp.finding_id: LLMClassification("false_positive", 0.95, "", "ignore", "m", True),
        }
        targets = _cost_aware_targets([real, env_ref, llm_fp, pk], classifications, self.config)
        target_ids = {f.finding_id for f in targets}
        self.assertIn(real.finding_id, target_ids)
        self.assertIn(pk.finding_id, target_ids)
        self.assertNotIn(env_ref.finding_id, target_ids)
        self.assertNotIn(llm_fp.finding_id, target_ids)


class ProviderFloorAndLLMStageTests(unittest.TestCase):
    def setUp(self):
        self.config = CredHunterConfig()
        self.config.scan.fail_on = "critical"
        self.config.llm.enabled = True
        self.config.llm.rank = True
        self.config.llm.explain = True
        self.config.llm.remediate = True

    def test_generic_github_token_gets_provider_floor_and_fails_critical(self):
        finding = _finding(
            file_path="src/hardcoded_realistic.py",
            line_number=12,
            raw_secret="ghp_xxxxxxxxxxxxxxxxxxxx",
            secret_type="generic_secret",
        )
        finding.metadata["target_line"] = 'GITHUB_TOKEN = "gh****xx"'

        decision = evaluate_findings([finding], self.config)
        item = decision.findings[0]

        self.assertEqual(item.finding.secret_type, "github_token")
        self.assertGreaterEqual(item.risk_score.score, 90)
        self.assertEqual(item.risk_level, "critical")
        self.assertEqual(item.action, "fail")
        self.assertEqual(item.risk_score.risk_floor["provider"], "github_token")

    def test_full_llm_stages_attempted_for_non_ignored_github_token(self):
        finding = _finding(
            file_path="src/hardcoded_realistic.py",
            line_number=12,
            raw_secret="ghp_1234567890abcdef123456",
            secret_type="generic_secret",
        )
        finding.metadata["target_line"] = 'GITHUB_TOKEN = "gh****56"'

        calls = {"classify": 0, "rank": 0, "explain": 0, "remediate": 0}

        def classify(payload, active_config):
            calls["classify"] += 1
            return {
                "classification": "true_positive",
                "confidence": 0.95,
                "reason": "Provider token in source.",
                "recommended_action": "block",
            }

        def rank(payload, active_config):
            calls["rank"] += 1
            return {"score": 33, "rationale": "Model under-ranked this token."}

        def explain(payload, active_config):
            calls["explain"] += 1
            return {"explanation": "A GitHub token is hardcoded in application source."}

        def remediate(payload, active_config):
            calls["remediate"] += 1
            return {"steps": ["Revoke the GitHub token.", "Move it to GitHub Actions Secrets."]}

        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            classifications = LLMFilterService(self.config, classifier=classify).classify_findings([finding], self.config)
            rankings = LLMRankerService(self.config, ranker=rank).rank_findings([finding], classifications, self.config)
            explanations = LLMExplainerService(self.config, explainer=explain).explain_findings(
                [finding], classifications, rankings, self.config
            )
            remediations = LLMRemediationService(self.config, remediator=remediate).remediate_findings(
                [finding], classifications, rankings, self.config
            )
            decision = evaluate_findings(
                [finding],
                self.config,
                llm_classifications=classifications,
                llm_rankings=rankings,
                llm_explanations=explanations,
                llm_remediations=remediations,
            )

        item = decision.findings[0]
        self.assertEqual(calls, {"classify": 1, "rank": 1, "explain": 1, "remediate": 1})
        self.assertTrue(item.llm_classification.used)
        self.assertTrue(item.llm_ranking.used)
        self.assertTrue(item.llm_explanation.used)
        self.assertTrue(item.llm_remediation.used)
        self.assertGreaterEqual(item.risk_score.score, 90)
        self.assertEqual(item.risk_score.risk_floor["provider"], "github_token")

    def test_placeholder_is_ignored_and_skips_llm_stages(self):
        finding = _finding(secret_type="stripe_api_key", raw_secret="YOUR_API_KEY_HERE")
        finding.metadata["target_line"] = 'STRIPE_API_KEY = "YOUR_API_KEY_HERE"'
        calls = {"classify": 0}

        def classify(payload, active_config):
            calls["classify"] += 1
            return {"classification": "true_positive", "confidence": 0.9}

        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            classifications = LLMFilterService(self.config, classifier=classify).classify_findings([finding], self.config)
            rankings = LLMRankerService(self.config, ranker=lambda p, c: {"score": 90}).rank_findings(
                [finding], classifications, self.config
            )
            explanations = LLMExplainerService(self.config, explainer=lambda p, c: {"explanation": "x"}).explain_findings(
                [finding], classifications, rankings, self.config
            )
            remediations = LLMRemediationService(self.config, remediator=lambda p, c: {"steps": ["x"]}).remediate_findings(
                [finding], classifications, rankings, self.config
            )
            decision = evaluate_findings(
                [finding],
                self.config,
                llm_classifications=classifications,
                llm_rankings=rankings,
                llm_explanations=explanations,
                llm_remediations=remediations,
            )

        item = decision.findings[0]
        self.assertEqual(calls["classify"], 0)
        self.assertEqual(item.action, "ignore")
        self.assertEqual(item.false_positive_assessment.classification, "false_positive")
        self.assertFalse(item.llm_classification.used)
        self.assertFalse(item.llm_ranking.used)
        self.assertFalse(item.llm_explanation.used)
        self.assertFalse(item.llm_remediation.used)


class MarkdownSummaryTests(unittest.TestCase):
    def _decision(self) -> CIDecision:
        finding = _finding(secret_type="github_token", file_path="src/config.py", line_number=12, raw_secret="ghp_abcdefghijklmnopqrstuvwx")
        item = FindingDecision(
            finding=finding,
            risk_level="high",
            action="manual_review",
            reason="A GitHub token appears hardcoded in source.",
            llm_classification=LLMClassification("likely_true_positive", 0.91, "", "warn", "m", True),
        )
        return CIDecision(
            action="manual_review", exit_code=0, finding_count=1, blocking_count=0,
            warning_count=0, manual_review_count=1, ignored_count=0, findings=[item],
        )

    def test_renders_remediation_card_without_raw_secret(self):
        report = build_markdown_summary(self._decision())
        self.assertIn("High Risk", report)
        self.assertIn("Safe code pattern", report)
        self.assertIn("os.getenv", report)
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwx", report)

    def test_empty_decision_reports_no_findings(self):
        decision = CIDecision(
            action="pass", exit_code=0, finding_count=0, blocking_count=0,
            warning_count=0, manual_review_count=0, ignored_count=0, findings=[],
        )
        self.assertIn("No reportable findings", build_markdown_summary(decision))

    def test_report_shows_enabled_and_used_llm_stages(self):
        finding = _finding(secret_type="github_token", file_path="src/config.py", line_number=12)
        item = FindingDecision(
            finding=finding,
            risk_level="high",
            action="manual_review",
            reason="Hardcoded token.",
            llm_classification=LLMClassification("likely_true_positive", 0.91, "real token", "warn", "o4-mini", True),
            llm_ranking=LLMRanking(72, "high", "manual_review", "urgent", "o4-mini", True),
            llm_explanation=LLMExplanation("This token is hardcoded in source.", "o4-mini", True),
            llm_remediation=LLMRemediation(["Rotate the token.", "Move it to a secret store."], "o4-mini", True),
        )
        decision = CIDecision(
            action="manual_review",
            exit_code=0,
            finding_count=1,
            blocking_count=0,
            warning_count=0,
            manual_review_count=1,
            ignored_count=0,
            findings=[item],
            llm_status={
                "mode": "llm",
                "enabled": True,
                "model": "o4-mini",
                "stages": {"classify": "active", "rank": "active", "explain": "active", "remediate": "active"},
            },
        )
        report = build_markdown_summary(decision)
        self.assertIn("Engine: LLM-assisted", report)
        self.assertIn("Model: `o4-mini`", report)
        self.assertIn("LLM stages enabled: classify, rank, explain, remediate", report)
        self.assertIn("classify=used; rank=used; explain=used; remediate=used", report)
        self.assertIn("risk_floor=none", report)
        self.assertIn("llm_filter.used=true", report)
        self.assertIn("llm_ranker.used=true", report)
        self.assertIn("llm_explanation.used=true", report)
        self.assertIn("llm_remediation.used=true", report)

    def test_report_shows_risk_floor_when_applied(self):
        finding = _finding(secret_type="github_token", file_path="src/config.py", line_number=12)
        item = FindingDecision(
            finding=finding,
            risk_level="critical",
            action="fail",
            reason="Hardcoded token.",
            risk_score=RiskScore(
                90,
                "critical",
                "fail",
                risk_floor={"provider": "github_token", "minimum_score": 90},
            ),
            llm_classification=LLMClassification("true_positive", 0.91, "real token", "block", "o4-mini", True),
        )
        decision = CIDecision(
            action="fail",
            exit_code=1,
            finding_count=1,
            blocking_count=1,
            warning_count=0,
            manual_review_count=0,
            ignored_count=0,
            findings=[item],
        )
        report = build_markdown_summary(decision)
        html = build_html_report(decision)
        self.assertIn("risk_floor=github_token:90", report)
        self.assertIn("risk_floor=github_token:90", html)

    def test_false_positive_classification_is_hidden_from_main_table(self):
        finding = _finding(secret_type="generic_secret", file_path="src/config.py", line_number=2)
        item = FindingDecision(
            finding=finding,
            risk_level="medium",
            action="warn",
            reason="LLM considered this a false positive.",
            llm_classification=LLMClassification("false_positive", 0.95, "placeholder", "ignore", "o4-mini", True),
        )
        decision = CIDecision(
            action="warn", exit_code=0, finding_count=1, blocking_count=0,
            warning_count=1, manual_review_count=0, ignored_count=0, findings=[item],
        )
        report = build_pr_comment(decision)
        self.assertIn("No reportable findings", report)
        self.assertNotIn("|  | medium | warn | generic_secret |", report)


class HtmlReportTests(unittest.TestCase):
    def _decision(self, **finding_overrides) -> CIDecision:
        finding = _finding(
            secret_type=finding_overrides.pop("secret_type", "github_token"),
            file_path=finding_overrides.pop("file_path", "src/config.py"),
            line_number=finding_overrides.pop("line_number", 12),
            raw_secret=finding_overrides.pop("raw_secret", "ghp_abcdefghijklmnopqrstuvwx"),
            **finding_overrides,
        )
        item = FindingDecision(
            finding=finding,
            risk_level="high",
            action="manual_review",
            reason="A GitHub token appears hardcoded in source.",
            llm_classification=LLMClassification("likely_true_positive", 0.91, "", "warn", "m", True),
        )
        return CIDecision(
            action="manual_review", exit_code=0, finding_count=1, blocking_count=0,
            warning_count=0, manual_review_count=1, ignored_count=0, findings=[item],
        )

    def test_is_self_contained_html_with_card(self):
        report = build_html_report(self._decision())
        self.assertTrue(report.lstrip().lower().startswith("<!doctype html>"))
        self.assertIn("<style>", report)  # inlined CSS, no external assets
        self.assertNotIn("http://", report)
        self.assertNotIn("https://", report)
        self.assertIn("CredHunter-X Report", report)
        self.assertIn("Safe code pattern", report)
        self.assertIn("os.getenv", report)

    def test_never_exposes_raw_secret(self):
        report = build_html_report(self._decision())
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwx", report)

    def test_escapes_finding_text(self):
        # A file path containing markup must not inject into the page.
        report = build_html_report(self._decision(file_path="src/<script>x</script>.py"))
        self.assertNotIn("<script>x</script>", report)
        self.assertIn("&lt;script&gt;", report)

    def test_empty_decision_reports_no_findings(self):
        decision = CIDecision(
            action="pass", exit_code=0, finding_count=0, blocking_count=0,
            warning_count=0, manual_review_count=0, ignored_count=0, findings=[],
        )
        report = build_html_report(decision)
        self.assertIn("No reportable findings", report)


class HtmlReportContextTests(unittest.TestCase):
    def test_renders_masked_context_not_raw_neighbour(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "config.py"
            target.write_text(
                'PREV = "anotherlongsecretvalue12345"\n'
                'API_KEY = "sk_live_abcdefghijklmnopqrstuv"\n'
                "client.use(API_KEY)\n",
                encoding="utf-8",
            )
            finding = _finding(file_path="config.py", line_number=2, raw_secret="sk_live_abcdefghijklmnopqrstuv")
            enrich_with_source_context([finding], tmp, before=1, after=1)
            item = FindingDecision(
                finding=finding, risk_level="high", action="manual_review",
                reason="Hardcoded secret.",
            )
            decision = CIDecision(
                action="manual_review", exit_code=0, finding_count=1, blocking_count=0,
                warning_count=0, manual_review_count=1, ignored_count=0, findings=[item],
            )
            report = build_html_report(decision)
            self.assertNotIn("anotherlongsecretvalue12345", report)
            self.assertNotIn("sk_live_abcdefghijklmnopqrstuv", report)


if __name__ == "__main__":
    unittest.main()
