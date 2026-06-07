from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.ci.config import CredHunterConfig
from app.ci.decision import evaluate_findings
from app.evaluation.creddata_loader import load_balanced_creddata_sample, load_creddata_records, summarize_records


def run_phase9_dataset_check(limit: int = 50, balanced: bool = False) -> dict:
    if balanced:
        records = load_balanced_creddata_sample(per_label=max(1, limit // 2))
    else:
        records = load_creddata_records(limit=limit)

    findings = [record.to_finding() for record in records]
    config = CredHunterConfig()
    config.scan.fail_on = "critical"
    decision = evaluate_findings(findings, config)

    return {
        "dataset": "CredData",
        "record_summary": summarize_records(records),
        "decision": {
            "action": decision.action,
            "finding_count": decision.finding_count,
            "blocking_count": decision.blocking_count,
            "manual_review_count": decision.manual_review_count,
            "warning_count": decision.warning_count,
            "ignored_count": decision.ignored_count,
        },
        "sample_findings": [finding.to_dict() for finding in decision.findings[:5]],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="credhunter-phase9")
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--balanced", action="store_true")
    parser.add_argument("--output", help="Optional JSON output path.")
    args = parser.parse_args(argv)

    result = run_phase9_dataset_check(args.limit, args.balanced)
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
