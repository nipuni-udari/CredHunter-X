"""Demo evaluation: GitLeaks-style regex baseline vs the CredHunter-X pipeline.

This runs over the labelled demo project (``../demo`` by default) and reports,
against ground-truth labels, how a raw regex/entropy scanner compares with the
CredHunter-X pipeline:

- **baseline**   : every detected candidate is reported (GitLeaks-style — pattern
  matching with no context). Recall is 1.0 by construction; precision suffers
  because every fake token is also reported.
- **rules_only** : CredHunter-X deterministic rule filter + risk scoring.
- **pipeline**   : rules + the LLM stages (classify/rank/explain/remediate). Only
  differs from rules_only when ``OPENAI_API_KEY`` is set; otherwise the LLM
  stages skip and this column equals rules_only.

Candidates come from the bundled regex scanner (``source_scanner``) by default so
the demo is fully reproducible with no external tools. Pass ``--gitleaks-report``
to score a real Gitleaks JSON/SARIF report instead.

Usage:

    # 1. list detected candidates (used once to build ground_truth.json)
    python -m app.evaluation.demo_runner --project ../demo --list

    # 2. run the comparison
    python -m app.evaluation.demo_runner --project ../demo
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from app.ci.config import load_config
from app.ci.decision import CIDecision, evaluate_findings
from app.scanner.gitleaks_parser import parse_gitleaks_report
from app.scanner.models import NormalizedFinding
from app.scanner.source_scanner import scan_path
from app.services.llm_filter_service import LLMFilterService

# Actions that mean "surfaced to the developer as a finding" (i.e. predicted
# positive). pass/ignore mean the pipeline judged it not worth reporting.
FLAGGED_ACTIONS = {"warn", "manual_review", "fail"}
POSITIVE_LABEL = "true_secret"
NEGATIVE_LABEL = "false_positive"

# Dataset metadata files are not part of the code under test; skip any candidates
# the scanner finds inside them (e.g. example tokens quoted in the labels file).
EXCLUDED_BASENAMES = {"ground_truth.json", ".credhunter.yml"}


def _key(file_path: str, line: int | None) -> str:
    return f"{file_path.replace(chr(92), '/')}:{line or 1}"


def _load_findings(args) -> list[NormalizedFinding]:
    if args.gitleaks_report:
        findings = parse_gitleaks_report(args.gitleaks_report)
    else:
        findings = scan_path(args.project)
    return [f for f in findings if Path(f.file_path).name not in EXCLUDED_BASENAMES]


def _metrics(tp: int, fp: int, tn: int, fn: int) -> dict:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
    }


def _score(findings, labels, decision: CIDecision, baseline: bool) -> tuple[dict, list[dict]]:
    decided = {d.finding.finding_id: d for d in decision.findings}
    tp = fp = tn = fn = 0
    rows: list[dict] = []
    for finding in findings:
        key = _key(finding.file_path, finding.line_number)
        if key not in labels:
            continue
        actual_positive = labels[key]["label"] == POSITIVE_LABEL
        decided_finding = decided[finding.finding_id]
        flagged = True if baseline else decided_finding.action in FLAGGED_ACTIONS

        if flagged and actual_positive:
            tp += 1
        elif flagged and not actual_positive:
            fp += 1
        elif not flagged and actual_positive:
            fn += 1
        else:
            tn += 1

        if not baseline:
            rows.append(
                {
                    "key": key,
                    "secret_type": finding.secret_type,
                    "truth": labels[key]["label"],
                    "action": decided_finding.action,
                    "flagged": flagged,
                    "correct": flagged == actual_positive,
                    "explanation": decided_finding.explanation(),
                }
            )
    return _metrics(tp, fp, tn, fn), rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="credhunter-demo")
    parser.add_argument("--project", default="../demo", help="Path to the demo project.")
    parser.add_argument("--config", help="Config path (defaults to <project>/.credhunter.yml).")
    parser.add_argument("--gitleaks-report", help="Score a real Gitleaks JSON/SARIF report instead of the bundled scanner.")
    parser.add_argument("--ground-truth", help="Ground-truth labels (defaults to <project>/ground_truth.json).")
    parser.add_argument("--list", action="store_true", help="List detected candidates and exit (used to build ground truth).")
    parser.add_argument("--json-output", help="Write the full result as JSON.")
    args = parser.parse_args(argv)

    project = Path(args.project)
    findings = _load_findings(args)

    if args.list:
        for finding in sorted(findings, key=lambda f: (f.file_path, f.line_number or 0)):
            print(
                json.dumps(
                    {
                        "key": _key(finding.file_path, finding.line_number),
                        "secret_type": finding.secret_type,
                        "redacted": finding.redacted_secret,
                    }
                )
            )
        print(f"\n# {len(findings)} candidates detected", file=sys.stderr)
        return 0

    gt_path = Path(args.ground_truth) if args.ground_truth else project / "ground_truth.json"
    ground_truth = json.loads(gt_path.read_text(encoding="utf-8"))
    labels = ground_truth.get("labels", ground_truth)

    config = load_config(args.config or str(project / ".credhunter.yml"))

    # rules-only decision (no LLM classifications passed).
    rules_decision = evaluate_findings(findings, config)

    # full pipeline decision (LLM stages run only if enabled + key present).
    llm_classifications = None
    if config.llm.enabled and findings:
        llm_classifications = LLMFilterService(config).classify_findings(findings, config)
    pipeline_decision = evaluate_findings(findings, config, llm_classifications)

    labelled = [f for f in findings if _key(f.file_path, f.line_number) in labels]
    unlabelled = [_key(f.file_path, f.line_number) for f in findings if _key(f.file_path, f.line_number) not in labels]

    baseline_metrics, _ = _score(findings, labels, rules_decision, baseline=True)
    rules_metrics, _ = _score(findings, labels, rules_decision, baseline=False)
    pipeline_metrics, rows = _score(findings, labels, pipeline_decision, baseline=False)

    llm_used = any(
        c.used for c in (llm_classifications or {}).values()
    ) if llm_classifications else False

    result = {
        "candidates": len(findings),
        "labelled": len(labelled),
        "unlabelled": unlabelled,
        "label_counts": {
            POSITIVE_LABEL: sum(1 for v in labels.values() if v["label"] == POSITIVE_LABEL),
            NEGATIVE_LABEL: sum(1 for v in labels.values() if v["label"] == NEGATIVE_LABEL),
        },
        "llm_active": llm_used,
        "metrics": {
            "baseline_regex": baseline_metrics,
            "rules_only": rules_metrics,
            "pipeline": pipeline_metrics,
        },
        "findings": rows,
    }

    _print_report(result)

    if args.json_output:
        out = Path(args.json_output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"\nWrote {out}")

    return 0


def _print_report(result: dict) -> None:
    m = result["metrics"]
    lc = result["label_counts"]
    print("=" * 72)
    print("CredHunter-X demo: GitLeaks-style regex baseline vs the LLM pipeline")
    print("=" * 72)
    print(
        f"Candidates: {result['candidates']}  "
        f"(real={lc[POSITIVE_LABEL]}, fake={lc[NEGATIVE_LABEL]})  "
        f"LLM active: {result['llm_active']}"
    )
    if result["unlabelled"]:
        print(f"WARNING: {len(result['unlabelled'])} unlabelled candidate(s): {result['unlabelled']}")
    print()
    header = f"{'approach':<16}{'precision':>11}{'recall':>9}{'f1':>8}{'TP':>5}{'FP':>5}{'TN':>5}{'FN':>5}"
    print(header)
    print("-" * len(header))
    for name, key in (("GitLeaks (regex)", "baseline_regex"), ("rules_only", "rules_only"), ("pipeline", "pipeline")):
        x = m[key]
        print(
            f"{name:<16}{x['precision']:>11}{x['recall']:>9}{x['f1']:>8}"
            f"{x['tp']:>5}{x['fp']:>5}{x['tn']:>5}{x['fn']:>5}"
        )
    base_fp = m["baseline_regex"]["fp"]
    pipe_fp = m["pipeline"]["fp"]
    if base_fp:
        print(f"\nFalse-positive reduction (pipeline vs baseline): {round(100 * (base_fp - pipe_fp) / base_fp, 1)}%")

    print("\nPer-finding decisions (pipeline):")
    for row in sorted(result["findings"], key=lambda r: (r["truth"], r["key"])):
        mark = "OK " if row["correct"] else "XX "
        print(f"  {mark}{row['key']:<34} {row['truth']:<14} -> {row['action']:<13} [{row['secret_type']}]")


if __name__ == "__main__":
    raise SystemExit(main())
