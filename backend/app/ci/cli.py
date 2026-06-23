from __future__ import annotations

import argparse
import os
import sys

from app.scanner.gitleaks_parser import parse_gitleaks_report
from app.services.llm_explainer_service import LLMExplainerService
from app.services.llm_filter_service import LLMFilterService
from app.services.llm_ranker_service import LLMRankerService
from app.services.llm_remediation_service import LLMRemediationService

from .backend_client import BackendSubmissionError, submit_scan_to_backend
from .config import load_config
from .decision import evaluate_findings
from .reports import write_github_summary, write_json_report, write_pr_comment, write_sarif_report


CONFIG_ERROR = 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="credhunter-ci")
    parser.add_argument("--gitleaks-report", required=True, help="Path to Gitleaks JSON or SARIF report.")
    parser.add_argument("--config", default=".credhunter.yml", help="CredHunter-X config path.")
    parser.add_argument("--json-output", default="credhunter-report.json", help="Output JSON report path.")
    parser.add_argument("--sarif-output", default="credhunter-report.sarif", help="Output SARIF report path.")
    parser.add_argument("--summary-output", help="Output Markdown summary path. Defaults to GITHUB_STEP_SUMMARY.")
    parser.add_argument("--pr-comment-output", help="Optional PR comment Markdown output path.")
    parser.add_argument("--fail-on", help="Override configured fail_on threshold.")
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

        if os.path.exists(args.gitleaks_report):
            findings = parse_gitleaks_report(args.gitleaks_report)
        else:
            sys.stderr.write(
                f"CredHunter-X: Gitleaks report not found at '{args.gitleaks_report}'; "
                "treating as a clean scan with no findings.\n"
            )
            findings = []

        # The LLM pipeline is optional and self-contained: each stage calls OpenAI
        # directly, so no CredHunter backend needs to be hosted. When disabled, or
        # when no API key is present, stages are skipped and the deterministic
        # rules / templates decide. Stages run in order classify -> rank ->
        # explain -> remediate, each consuming the previous stage's output.
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
            if config.llm.explain:
                llm_explanations = LLMExplainerService(config).explain_findings(
                    findings, llm_classifications, llm_rankings, config
                )
            if config.llm.remediate:
                llm_remediations = LLMRemediationService(config).remediate_findings(
                    findings, llm_classifications, llm_rankings, config
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


def _print_console_summary(decision, backend_scan=None) -> None:
    scan_text = f", backend_scan_id={backend_scan['scan_id']}" if backend_scan else ""
    sys.stdout.write(
        "CredHunter-X: "
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
