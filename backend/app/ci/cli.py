from __future__ import annotations

import argparse
import os
import sys

from app.scanner.candidate_merger import merge_and_dedupe
from app.scanner.gitleaks_parser import parse_gitleaks_report
from app.scanner.models import NormalizedFinding
from app.scanner.python_candidate_extractor import extract_python_candidates
from app.scanner.source_context import DEFAULT_CONTEXT_LINES, enrich_with_source_context
from app.services.false_positive_filter import assess_false_positive
from app.services.llm_filter_service import LLMClassification, LLMFilterService
from app.services.llm_explainer_service import LLMExplainerService
from app.services.llm_ranker_service import LLMRankerService
from app.services.llm_remediation_service import LLMRemediationService

from .backend_client import BackendSubmissionError, submit_scan_to_backend
from .config import CredHunterConfig, load_config
from .decision import evaluate_findings
from .reports import (
    write_github_summary,
    write_html_report,
    write_json_report,
    write_markdown_summary,
    write_pr_comment,
    write_sarif_report,
)


CONFIG_ERROR = 2

# Classifications that mean "do not spend explain/remediate calls on this".
_NON_SECRET_LABELS = {"false_positive", "likely_false_positive"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="credhunter-ci")
    parser.add_argument("--gitleaks-report", required=True, help="Path to Gitleaks JSON or SARIF report.")
    parser.add_argument("--config", default=".credhunter.yml", help="CredHunter-X config path.")
    parser.add_argument(
        "--scan-path",
        default=".",
        help="Repository/source root used for context enrichment and the Python extractor.",
    )
    parser.add_argument("--json-output", default="credhunter-report.json", help="Output JSON report path.")
    parser.add_argument("--sarif-output", default="credhunter-report.sarif", help="Output SARIF report path.")
    parser.add_argument("--summary-output", help="Output Markdown summary path. Defaults to GITHUB_STEP_SUMMARY.")
    parser.add_argument("--markdown-output", help="Optional developer-friendly Markdown report (remediation cards).")
    parser.add_argument("--html-output", help="Optional self-contained HTML developer report (remediation cards; print-to-PDF).")
    parser.add_argument("--pr-comment-output", help="Optional PR comment Markdown output path.")
    parser.add_argument("--fail-on", help="Override configured fail_on threshold.")
    parser.add_argument(
        "--context-lines",
        type=int,
        default=DEFAULT_CONTEXT_LINES,
        help="Number of source lines of context to attach before/after each finding.",
    )
    parser.add_argument(
        "--no-python-extractor",
        action="store_true",
        help="Disable the Python AST candidate extractor (Gitleaks findings only).",
    )
    parser.add_argument(
        "--no-llm-cache",
        action="store_true",
        help="Disable the on-disk LLM response cache for this run.",
    )
    parser.add_argument(
        "--enable-llm",
        action="store_true",
        help="Run the LLM classifier on ambiguous findings (requires OPENAI_API_KEY).",
    )
    parser.add_argument(
        "--llm-workflow",
        choices=["single", "agentic"],
        help="LLM workflow when LLM is enabled (default: configured value).",
    )
    parser.add_argument(
        "--llm-rank",
        action="store_true",
        help="Run the LLM Ranker to refine risk scores (requires --enable-llm).",
    )
    parser.add_argument(
        "--llm-explain",
        action="store_true",
        help="Run the LLM Explainer for developer-facing rationales (requires --enable-llm).",
    )
    parser.add_argument(
        "--llm-remediate",
        action="store_true",
        help="Run the LLM Remediation stage for tailored fix steps (requires --enable-llm).",
    )

    args = parser.parse_args(argv)

    if args.no_llm_cache:
        os.environ["CREDHUNTER_LLM_CACHE"] = "false"

    try:
        config = load_config(args.config)
        if args.fail_on:
            config.scan.fail_on = args.fail_on.lower()
        if args.enable_llm:
            config.llm.enabled = True
        if args.llm_workflow:
            config.llm.workflow = args.llm_workflow
        if args.llm_rank:
            config.llm.rank = True
        if args.llm_explain:
            config.llm.explain = True
        if args.llm_remediate:
            config.llm.remediate = True

        findings = _generate_candidates(args)

        # The LLM pipeline is optional and self-contained: each stage calls OpenAI
        # directly (with on-disk caching), so no CredHunter backend needs to be
        # hosted. When disabled, or when no API key is present, stages are skipped
        # and the deterministic rules / templates decide.
        #
        # Cost-aware ordering: classify and rank everything, but only spend the
        # explain/remediate calls on findings that survive as likely secrets --
        # obvious false positives (rule-ignored, env references, or LLM-rejected)
        # never reach those stages.
        llm_classifications = None
        llm_rankings = None
        llm_explanations = None
        llm_remediations = None
        if config.llm.enabled and findings:
            llm_classifications = LLMFilterService(config).classify_findings(findings, config)
            if config.llm.rank:
                llm_rankings = LLMRankerService(config).rank_findings(
                    findings, llm_classifications, config
                )
            targets = _cost_aware_targets(findings, llm_classifications, config)
            if config.llm.explain:
                llm_explanations = LLMExplainerService(config).explain_findings(
                    targets, llm_classifications, llm_rankings, config
                )
            if config.llm.remediate:
                llm_remediations = LLMRemediationService(config).remediate_findings(
                    targets, llm_classifications, llm_rankings, config
                )

        decision = evaluate_findings(
            findings,
            config,
            llm_classifications,
            llm_rankings=llm_rankings,
            llm_explanations=llm_explanations,
            llm_remediations=llm_remediations,
        )
        backend_scan = None

        if config.backend.url:
            backend_scan = submit_scan_to_backend(config.backend.url, findings, config)

        write_json_report(decision, args.json_output)
        write_sarif_report(decision, args.sarif_output)

        summary_path = args.summary_output or os.getenv("GITHUB_STEP_SUMMARY")
        if summary_path:
            write_github_summary(decision, summary_path)
        if args.markdown_output:
            write_markdown_summary(decision, args.markdown_output)
        if args.html_output:
            write_html_report(decision, args.html_output)
        if args.pr_comment_output:
            write_pr_comment(decision, args.pr_comment_output)

        _print_console_summary(decision, backend_scan)
        return decision.exit_code
    except BackendSubmissionError as exc:
        sys.stderr.write(f"CredHunter-X backend submission error: {exc}\n")
        return CONFIG_ERROR
    except Exception as exc:
        sys.stderr.write(f"CredHunter-X CI error: {exc}\n")
        return CONFIG_ERROR


def _generate_candidates(args) -> list[NormalizedFinding]:
    """Run the candidate generators, merge/dedupe them, and enrich with context.

    Gitleaks remains the primary generator; the Python AST extractor adds
    language-specific candidates Gitleaks misses. Both are merged and
    deduplicated, then each surviving finding gets masked source context for the
    filter and LLM stages.
    """

    if os.path.exists(args.gitleaks_report):
        gitleaks_findings = parse_gitleaks_report(args.gitleaks_report)
    else:
        sys.stderr.write(
            f"CredHunter-X: Gitleaks report not found at '{args.gitleaks_report}'; "
            "treating as a clean scan with no Gitleaks findings.\n"
        )
        gitleaks_findings = []

    python_findings: list[NormalizedFinding] = []
    if not args.no_python_extractor and os.path.exists(args.scan_path):
        try:
            python_findings = extract_python_candidates(args.scan_path)
        except Exception as exc:  # noqa: BLE001 - extraction is best-effort.
            sys.stderr.write(f"CredHunter-X: Python extractor error (ignored): {exc}\n")

    findings = merge_and_dedupe(gitleaks_findings, python_findings)

    if os.path.exists(args.scan_path):
        enrich_with_source_context(
            findings,
            args.scan_path,
            before=args.context_lines,
            after=args.context_lines,
        )
    return findings


def _cost_aware_targets(
    findings: list[NormalizedFinding],
    classifications: dict[str, LLMClassification] | None,
    config: CredHunterConfig,
) -> list[NormalizedFinding]:
    """Findings worth spending explain/remediate calls on.

    Drops anything the deterministic rules already ignore (placeholders, env
    references, configured paths) and anything the LLM classifier judged a
    (likely) false positive. Private keys are always kept; uncertain and
    unclassified findings are kept so a real secret never loses its remediation.
    """

    classifications = classifications or {}
    targets: list[NormalizedFinding] = []
    for finding in findings:
        if assess_false_positive(finding, config).ignored:
            continue
        if finding.secret_type == "private_key":
            targets.append(finding)
            continue
        classification = classifications.get(finding.finding_id)
        if classification and classification.used and classification.classification in _NON_SECRET_LABELS:
            continue
        targets.append(finding)
    return targets


def _print_console_summary(decision, backend_scan=None) -> None:
    scan_text = f", backend_scan_id={backend_scan['scan_id']}" if backend_scan else ""
    status = decision.llm_status or {}
    engine = status.get("mode", "deterministic")
    if engine == "fallback":
        engine = f"fallback ({status.get('reason', 'unknown')})"
    sys.stdout.write(
        "CredHunter-X: "
        f"engine={engine}, "
        f"action={decision.action}, "
        f"findings={decision.finding_count}, "
        f"blocking={decision.blocking_count}, "
        f"manual_review={decision.manual_review_count}, "
        f"warnings={decision.warning_count}, "
        f"ignored={decision.ignored_count}"
        f"{scan_text}\n"
    )


if __name__ == "__main__":
    raise SystemExit(main())
