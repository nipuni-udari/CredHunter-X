"""Explanation-quality evaluation (research question RQ3).

RQ3 asks whether the generated explanations are technically correct and useful
for a developer remediating a finding. This module scores each explanation with
deterministic, auditable checks and (optionally) an injectable LLM-as-judge.

Automated checks per explanation:

- ``schema_valid``     : classification and recommended_action are in range and reason is present.
- ``non_trivial``      : the reason is a real sentence, not empty/boilerplate-short.
- ``no_secret_leak``   : the reason does not echo the raw secret / private-key body.
- ``references_context``: the reason grounds itself in the finding (type, path, or a known signal).
- ``action_consistent``: recommended_action matches the classification polarity.
- ``label_correct``    : classification polarity matches ground truth (when provided).

The aggregate ``score`` is the mean of the applicable checks. A judge hook can
add a human-like 0..1 usefulness score for a sampled subset.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from app.scanner.models import NormalizedFinding
from app.services.llm_filter_service import LLM_LABELS, LLMClassification

ALLOWED_ACTIONS = {"block", "warn", "ignore", "manual_review", "keep_rule_decision"}

POSITIVE_LABELS = {"true_positive", "likely_true_positive"}
NEGATIVE_LABELS = {"false_positive", "likely_false_positive"}

ACTION_CONSISTENCY = {
    "true_positive": {"block", "manual_review", "warn"},
    "likely_true_positive": {"block", "manual_review", "warn"},
    "uncertain": {"manual_review", "warn", "keep_rule_decision"},
    "likely_false_positive": {"ignore", "warn", "keep_rule_decision"},
    "false_positive": {"ignore", "keep_rule_decision"},
}

CONTEXT_KEYWORDS = {
    "secret", "token", "key", "password", "credential", "placeholder", "dummy",
    "example", "test", "fixture", "documentation", "docs", "config", "entropy",
    "hash", "uuid", "database", "local", "comment", "sample", "production",
    "private", "redacted", "format", "prefix",
}

MIN_REASON_LENGTH = 20


@dataclass(slots=True)
class ExplanationScore:
    finding_id: str
    used: bool
    checks: dict[str, bool] = field(default_factory=dict)
    score: float = 0.0
    judge_score: float | None = None
    judge_rationale: str | None = None

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "used": self.used,
            "checks": self.checks,
            "score": self.score,
            "judge_score": self.judge_score,
            "judge_rationale": self.judge_rationale,
        }


Judge = Callable[[NormalizedFinding, LLMClassification], dict]


def score_explanation(
    finding: NormalizedFinding,
    classification: LLMClassification,
    ground_truth: str | None = None,
    judge: Judge | None = None,
) -> ExplanationScore:
    if not classification.used:
        return ExplanationScore(finding_id=finding.finding_id, used=False, checks={}, score=0.0)

    reason = (classification.reason or "").strip()
    label = classification.classification.lower()
    action = classification.recommended_action.lower()

    checks: dict[str, bool] = {
        "schema_valid": label in LLM_LABELS and action in ALLOWED_ACTIONS and bool(reason),
        "non_trivial": len(reason) >= MIN_REASON_LENGTH and len(set(reason.split())) >= 4,
        "no_secret_leak": _no_secret_leak(reason, finding),
        "references_context": _references_context(reason, finding),
        "action_consistent": action in ACTION_CONSISTENCY.get(label, ALLOWED_ACTIONS),
    }
    if ground_truth is not None:
        checks["label_correct"] = _label_correct(label, ground_truth)

    score = round(sum(checks.values()) / len(checks), 6) if checks else 0.0
    result = ExplanationScore(
        finding_id=finding.finding_id, used=True, checks=checks, score=score
    )

    if judge is not None:
        verdict = judge(finding, classification)
        result.judge_score = _clamp(verdict.get("score"))
        result.judge_rationale = str(verdict.get("rationale", ""))[:500]

    return result


def evaluate_explanations(
    items: list[tuple[NormalizedFinding, LLMClassification, str | None]],
    judge: Judge | None = None,
) -> dict:
    scores = [score_explanation(f, c, gt, judge) for (f, c, gt) in items]
    used = [s for s in scores if s.used]

    check_names: set[str] = set()
    for s in used:
        check_names.update(s.checks)

    check_pass_rate = {
        name: round(
            sum(1 for s in used if s.checks.get(name)) / len(used), 6
        )
        for name in sorted(check_names)
    } if used else {}

    judged = [s for s in used if s.judge_score is not None]

    return {
        "explanations_scored": len(used),
        "explanations_skipped": len(scores) - len(used),
        "mean_quality_score": round(sum(s.score for s in used) / len(used), 6) if used else 0.0,
        "check_pass_rate": check_pass_rate,
        "mean_judge_score": round(sum(s.judge_score for s in judged) / len(judged), 6) if judged else None,
        "scores": [s.to_dict() for s in scores],
    }


def _no_secret_leak(reason: str, finding: NormalizedFinding) -> bool:
    lowered = reason.lower()
    if "-----begin" in lowered:
        return False
    redacted = (finding.redacted_secret or "").strip()
    # A safe marker like "<REDACTED_SECRET ...>" is fine to mention; a long
    # opaque value being echoed verbatim is not.
    if redacted and len(redacted) >= 12 and not redacted.startswith("<") and redacted.lower() in lowered:
        return False
    return True


def _references_context(reason: str, finding: NormalizedFinding) -> bool:
    lowered = reason.lower()
    type_tokens = finding.secret_type.lower().replace("_", " ").split()
    if any(token in lowered for token in type_tokens if len(token) > 2):
        return True
    if any(keyword in lowered for keyword in CONTEXT_KEYWORDS):
        return True
    path = finding.file_path.lower()
    suffix = path.rsplit(".", 1)[-1] if "." in path else ""
    return bool(suffix and suffix in lowered)


def _label_correct(label: str, ground_truth: str) -> bool:
    if ground_truth == "true_secret":
        return label in POSITIVE_LABELS
    if ground_truth == "false_positive":
        return label in NEGATIVE_LABELS
    return False


def _clamp(value: object) -> float:
    try:
        parsed = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(1.0, parsed))
