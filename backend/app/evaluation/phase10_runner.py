from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from app.ci.config import CredHunterConfig
from app.ci.decision import evaluate_findings
from app.evaluation.creddata_loader import load_balanced_creddata_sample, load_creddata_records
from app.evaluation.gitleaks_baseline import match_gitleaks_report_to_creddata
from app.evaluation.metrics import evaluate_decisions


def run_phase10_evaluation(
    limit: int | None = None,
    balanced: bool = False,
    gitleaks_report: str | None = None,
) -> dict:
    started = time.perf_counter()
    if balanced:
        per_label = 10 if limit is None else max(1, limit // 2)
        records = load_balanced_creddata_sample(per_label=per_label)
    else:
        records = load_creddata_records(limit=limit)

    findings = [record.to_finding() for record in records]
    config = CredHunterConfig()
    config.scan.fail_on = "critical"
    decision = evaluate_findings(findings, config)
    baseline_reported_ids = match_gitleaks_report_to_creddata(gitleaks_report, records) if gitleaks_report else None
    metrics = evaluate_decisions(records, decision, baseline_reported_ids)
    elapsed = time.perf_counter() - started

    return {
        "dataset": "CredData Python Eval",
        "mode": "balanced" if balanced else "sequential",
        "baseline_mode": "gitleaks_report" if gitleaks_report else "raw_creddata_candidates",
        "gitleaks_matched_findings": len(baseline_reported_ids) if baseline_reported_ids is not None else None,
        "runtime": {
            "seconds": round(elapsed, 6),
            "records_per_second": round(len(records) / elapsed, 3) if elapsed > 0 else 0,
        },
        "metrics": metrics,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="credhunter-phase10")
    parser.add_argument("--limit", type=int, help="Optional number of CredData records to evaluate.")
    parser.add_argument("--balanced", action="store_true", help="Use a balanced true/false sample.")
    parser.add_argument("--gitleaks-report", help="Optional Gitleaks JSON/SARIF report to use as baseline.")
    parser.add_argument("--output", help="Optional JSON output path.")
    args = parser.parse_args(argv)

    result = run_phase10_evaluation(args.limit, args.balanced, args.gitleaks_report)
    encoded = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(encoded + "\n", encoding="utf-8")
    else:
        print(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
