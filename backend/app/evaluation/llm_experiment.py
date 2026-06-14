"""LLM ablation experiment harness (research questions RQ1 and RQ2).

This runs the same CredData pipeline under several "arms" and compares them:

- ``baseline``    : raw scanner reports every candidate (no filtering).
- ``rules_only``  : deterministic rule-based false-positive filtering.
- ``llm_single``  : rules + single-prompt LLM classifier.
- ``llm_agentic`` : rules + multi-step (classify -> justify/verify) LLM classifier.

The LLM arms reuse the production ``LLMFilterService`` so the experiment reflects
real behaviour (including the cost-saving skip when a rule already settles a
finding). Classifiers are injectable: tests pass deterministic fakes, while real
experiments use the OpenAI classifiers selected by workflow.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import time
from pathlib import Path
from typing import Any, Callable

from app.ci.config import CredHunterConfig
from app.ci.decision import evaluate_findings
from app.evaluation.creddata_loader import (
    CredDataRecord,
    load_balanced_creddata_sample,
    load_creddata_records,
)
from app.evaluation.metrics import evaluate_decisions
from app.services.llm_filter_service import (
    LLMClassification,
    LLMFilterService,
    classifier_for_workflow,
)

Classifier = Callable[[dict[str, Any], CredHunterConfig], dict[str, Any]]

LLM_ARMS = {
    "llm_single": "single",
    "llm_agentic": "agentic",
}


def run_llm_ablation(
    records: list[CredDataRecord],
    *,
    classifiers: dict[str, Classifier] | None = None,
    base_config: CredHunterConfig | None = None,
    arms: list[str] | None = None,
    fail_on: str = "critical",
) -> dict:
    classifiers = classifiers or {}
    arms = arms or ["rules_only", "llm_single", "llm_agentic"]
    findings = [record.to_finding() for record in records]

    base_config = base_config or CredHunterConfig()
    base_config = copy.deepcopy(base_config)
    base_config.scan.fail_on = fail_on

    arm_results: dict[str, dict] = {}
    arm_assessments: dict[str, dict[str, LLMClassification]] = {}

    for arm in arms:
        if arm == "rules_only":
            decision = evaluate_findings(findings, base_config)
            arm_results[arm] = evaluate_decisions(records, decision)
            continue

        if arm not in LLM_ARMS:
            raise ValueError(f"Unknown experiment arm: {arm!r}")

        workflow = LLM_ARMS[arm]
        config = _arm_config(base_config, workflow)
        classifier = classifiers.get(arm) or classifier_for_workflow(workflow)
        service = LLMFilterService(config, classifier=classifier)
        assessments = service.classify_findings(findings, config)
        decision = evaluate_findings(findings, config, assessments)

        metrics = evaluate_decisions(records, decision)
        metrics["workflow_stats"] = _workflow_stats(assessments)
        arm_results[arm] = metrics
        arm_assessments[arm] = assessments

    comparison = _compare_arms(arm_results)
    if "llm_single" in arm_assessments and "llm_agentic" in arm_assessments:
        comparison["single_vs_agentic_agreement"] = _label_agreement(
            arm_assessments["llm_single"], arm_assessments["llm_agentic"]
        )

    return {
        "dataset": "CredData Python Eval",
        "record_count": len(records),
        "arms": arm_results,
        "comparison": comparison,
        "_assessments": arm_assessments,
    }


def _arm_config(base_config: CredHunterConfig, workflow: str) -> CredHunterConfig:
    config = copy.deepcopy(base_config)
    config.llm.enabled = True
    config.llm.workflow = workflow
    return config


def _workflow_stats(assessments: dict[str, LLMClassification]) -> dict:
    used = [a for a in assessments.values() if a.used]
    revised = sum(1 for a in used if a.metadata.get("label_revised"))
    return {
        "classified_by_llm": len(used),
        "skipped": sum(1 for a in assessments.values() if not a.used),
        "label_revised": revised,
        "label_revision_rate": round(revised / len(used), 6) if used else 0.0,
    }


def _compare_arms(arm_results: dict[str, dict]) -> dict:
    table = {}
    for name, metrics in arm_results.items():
        ch = metrics["credhunter_x"]
        table[name] = {
            "precision": ch["precision"],
            "recall": ch["recall"],
            "f1": ch["f1"],
            "false_positive_reduction": metrics["improvement"]["false_positive_reduction"],
        }
    return {"per_arm": table}


def _label_agreement(
    single: dict[str, LLMClassification],
    agentic: dict[str, LLMClassification],
) -> dict:
    shared = [fid for fid in single if fid in agentic]
    if not shared:
        return {"compared": 0, "agreement_rate": 0.0}
    agree = sum(1 for fid in shared if single[fid].classification == agentic[fid].classification)
    return {
        "compared": len(shared),
        "agree": agree,
        "agreement_rate": round(agree / len(shared), 6),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="credhunter-llm-ablation")
    parser.add_argument("--limit", type=int, help="Number of CredData records to evaluate.")
    parser.add_argument("--balanced", action="store_true", help="Use a balanced true/false sample.")
    parser.add_argument(
        "--arms",
        default="rules_only,llm_single,llm_agentic",
        help="Comma-separated arms to run.",
    )
    parser.add_argument("--output", help="Optional JSON output path.")
    args = parser.parse_args(argv)

    if args.balanced:
        per_label = 10 if args.limit is None else max(1, args.limit // 2)
        records = load_balanced_creddata_sample(per_label=per_label)
    else:
        records = load_creddata_records(limit=args.limit)

    arms = [arm.strip() for arm in args.arms.split(",") if arm.strip()]
    if any(arm in LLM_ARMS for arm in arms) and not os.getenv("OPENAI_API_KEY"):
        print("WARNING: OPENAI_API_KEY is not set; LLM arms will skip and fall back to rule decisions.")

    started = time.perf_counter()
    result = run_llm_ablation(records, arms=arms)
    result["runtime_seconds"] = round(time.perf_counter() - started, 6)
    result.pop("_assessments", None)

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
