from __future__ import annotations

from dataclasses import dataclass

from app.ci.decision import CIDecision
from app.evaluation.creddata_loader import CredDataRecord

POSITIVE_LABEL = "true_secret"
NEGATIVE_LABEL = "false_positive"
POSITIVE_ACTIONS = {"warn", "manual_review", "fail"}
NEGATIVE_ACTIONS = {"pass", "ignore"}
ESCALATED_ACTIONS = {"manual_review", "fail"}


@dataclass(slots=True)
class ConfusionMatrix:
    true_positive: int = 0
    false_positive: int = 0
    true_negative: int = 0
    false_negative: int = 0

    def to_dict(self) -> dict:
        return {
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "true_negative": self.true_negative,
            "false_negative": self.false_negative,
        }


def evaluate_decisions(
    records: list[CredDataRecord],
    decision: CIDecision,
    baseline_reported_ids: set[str] | None = None,
) -> dict:
    matrix = ConfusionMatrix()
    action_counts: dict[str, int] = {}
    label_action_counts: dict[str, dict[str, int]] = {}

    record_by_id = {record.candidate_id: record for record in records}

    for finding_decision in decision.findings:
        record = record_by_id[finding_decision.finding.finding_id]
        label = record.ground_truth
        action = finding_decision.action
        action_counts[action] = action_counts.get(action, 0) + 1
        label_action_counts.setdefault(label, {})
        label_action_counts[label][action] = label_action_counts[label].get(action, 0) + 1

        predicted_positive = action in POSITIVE_ACTIONS
        actual_positive = label == POSITIVE_LABEL

        if predicted_positive and actual_positive:
            matrix.true_positive += 1
        elif predicted_positive and not actual_positive:
            matrix.false_positive += 1
        elif not predicted_positive and actual_positive:
            matrix.false_negative += 1
        else:
            matrix.true_negative += 1

    baseline = _baseline_metrics(records, baseline_reported_ids)
    credhunter = _metrics_from_matrix(matrix)
    false_positive_reduction = _safe_ratio(
        baseline["confusion_matrix"]["false_positive"] - matrix.false_positive,
        baseline["confusion_matrix"]["false_positive"],
    )
    manual_review_reduction = _safe_ratio(
        len(records) - decision.manual_review_count,
        len(records),
    )

    return {
        "record_count": len(records),
        "label_counts": _label_counts(records),
        "baseline": baseline,
        "credhunter_x": {
            **credhunter,
            "confusion_matrix": matrix.to_dict(),
            "action_counts": action_counts,
            "label_action_counts": label_action_counts,
            "decision_action": decision.action,
            "blocking_count": decision.blocking_count,
            "manual_review_count": decision.manual_review_count,
            "warning_count": decision.warning_count,
            "ignored_count": decision.ignored_count,
        },
        "improvement": {
            "false_positive_reduction": false_positive_reduction,
            "manual_review_reduction": manual_review_reduction,
            "precision_delta": credhunter["precision"] - baseline["precision"],
            "recall_delta": credhunter["recall"] - baseline["recall"],
            "f1_delta": credhunter["f1"] - baseline["f1"],
        },
    }


def _baseline_metrics(records: list[CredDataRecord], reported_ids: set[str] | None) -> dict:
    if reported_ids is None:
        matrix = ConfusionMatrix(
            true_positive=sum(1 for record in records if record.ground_truth == POSITIVE_LABEL),
            false_positive=sum(1 for record in records if record.ground_truth == NEGATIVE_LABEL),
            true_negative=0,
            false_negative=0,
        )
        assumption = "Baseline reports every CredData candidate as a finding, matching raw scanner triage load."
    else:
        matrix = ConfusionMatrix()
        for record in records:
            reported = record.candidate_id in reported_ids
            actual_positive = record.ground_truth == POSITIVE_LABEL
            if reported and actual_positive:
                matrix.true_positive += 1
            elif reported and not actual_positive:
                matrix.false_positive += 1
            elif not reported and actual_positive:
                matrix.false_negative += 1
            else:
                matrix.true_negative += 1
        assumption = "Baseline uses matched findings from an external scanner report."

    return {
        **_metrics_from_matrix(matrix),
        "confusion_matrix": matrix.to_dict(),
        "assumption": assumption,
    }


def _metrics_from_matrix(matrix: ConfusionMatrix) -> dict:
    precision = _safe_ratio(matrix.true_positive, matrix.true_positive + matrix.false_positive)
    recall = _safe_ratio(matrix.true_positive, matrix.true_positive + matrix.false_negative)
    f1 = _safe_ratio(2 * precision * recall, precision + recall)
    false_positive_rate = _safe_ratio(matrix.false_positive, matrix.false_positive + matrix.true_negative)
    false_negative_rate = _safe_ratio(matrix.false_negative, matrix.false_negative + matrix.true_positive)
    accuracy = _safe_ratio(
        matrix.true_positive + matrix.true_negative,
        matrix.true_positive + matrix.true_negative + matrix.false_positive + matrix.false_negative,
    )
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": false_positive_rate,
        "false_negative_rate": false_negative_rate,
        "accuracy": accuracy,
    }


def _label_counts(records: list[CredDataRecord]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        counts[record.ground_truth] = counts.get(record.ground_truth, 0) + 1
    return counts


def _safe_ratio(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return round(numerator / denominator, 6)
