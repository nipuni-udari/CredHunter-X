from __future__ import annotations

import argparse
import os
import sys

from app.scanner.gitleaks_parser import parse_gitleaks_report

from .backend_client import BackendSubmissionError, submit_scan_to_backend
from .config import load_config
from .decision import evaluate_findings
from .reports import write_github_summary, write_json_report, write_sarif_report


CONFIG_ERROR = 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="credhunter-ci")
    parser.add_argument("--gitleaks-report", required=True, help="Path to Gitleaks JSON or SARIF report.")
    parser.add_argument("--config", default=".credhunter.yml", help="CredHunter-X config path.")
    parser.add_argument("--json-output", default="credhunter-report.json", help="Output JSON report path.")
    parser.add_argument("--sarif-output", default="credhunter-report.sarif", help="Output SARIF report path.")
    parser.add_argument("--summary-output", help="Output Markdown summary path. Defaults to GITHUB_STEP_SUMMARY.")
    parser.add_argument("--fail-on", help="Override configured fail_on threshold.")

    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
        if args.fail_on:
            config.scan.fail_on = args.fail_on.lower()

        findings = parse_gitleaks_report(args.gitleaks_report)
        decision = evaluate_findings(findings, config)
        backend_scan = None

        if config.backend.url:
            backend_scan = submit_scan_to_backend(config.backend.url, findings, config)

        write_json_report(decision, args.json_output)
        write_sarif_report(decision, args.sarif_output)

        summary_path = args.summary_output or os.getenv("GITHUB_STEP_SUMMARY")
        if summary_path:
            write_github_summary(decision, summary_path)

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
        f"warnings={decision.warning_count}, "
        f"ignored={decision.ignored_count}"
        f"{scan_text}\n"
    )


if __name__ == "__main__":
    raise SystemExit(main())
