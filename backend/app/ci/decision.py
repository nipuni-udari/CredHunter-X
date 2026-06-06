from __future__ import annotations

from dataclasses import dataclass

from app.scanner.models import NormalizedFinding
from app.services.false_positive_filter import FalsePositiveAssessment, assess_false_positive

from .config import CredHunterConfig

RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass(slots=True)
class FindingDecision:
    finding: NormalizedFinding
    risk_level: str
    action: str
    reason: str
    false_positive_assessment: FalsePositiveAssessment | None = None

    def to_dict(self) -> dict:
        payload = self.finding.to_dict()
        payload["risk_level"] = self.risk_level
        payload["action"] = self.action
        payload["decision_reason"] = self.reason
        if self.false_positive_assessment:
            payload["false_positive_filter"] = self.false_positive_assessment.to_metadata()
        return payload


@dataclass(slots=True)
class CIDecision:
    action: str
    exit_code: int
    finding_count: int
    blocking_count: int
    warning_count: int
    ignored_count: int
    findings: list[FindingDecision]

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "exit_code": self.exit_code,
            "finding_count": self.finding_count,
            "blocking_count": self.blocking_count,
            "warning_count": self.warning_count,
            "ignored_count": self.ignored_count,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def evaluate_findings(findings: list[NormalizedFinding], config: CredHunterConfig) -> CIDecision:
    decisions = [_evaluate_finding(finding, config) for finding in findings]
    blocking = [item for item in decisions if item.action == "fail"]
    warnings = [item for item in decisions if item.action == "warn"]
    ignored = [item for item in decisions if item.action == "ignore"]

    if blocking:
        action = "fail"
        exit_code = 1
    elif warnings:
        action = "warn"
        exit_code = 0
    else:
        action = "pass"
        exit_code = 0

    return CIDecision(
        action=action,
        exit_code=exit_code,
        finding_count=len(decisions),
        blocking_count=len(blocking),
        warning_count=len(warnings),
        ignored_count=len(ignored),
        findings=decisions,
    )


def _evaluate_finding(finding: NormalizedFinding, config: CredHunterConfig) -> FindingDecision:
    assessment = assess_false_positive(finding, config)
    if assessment.ignored:
        return FindingDecision(
            finding,
            assessment.risk_override or "low",
            "ignore",
            " ".join(assessment.reasons),
            assessment,
        )

    risk_level = _risk_level(finding)
    if assessment.risk_override and _risk_value(assessment.risk_override) < _risk_value(risk_level):
        risk_level = assessment.risk_override
    threshold = config.scan.fail_on

    if _risk_value(risk_level) >= _risk_value(threshold):
        return FindingDecision(
            finding,
            risk_level,
            "fail",
            f"Risk level is at or above fail_on={threshold}.",
            assessment,
        )

    if risk_level in {"medium", "high", "critical"}:
        return FindingDecision(
            finding,
            risk_level,
            "warn",
            "Finding is below blocking threshold but should be reviewed.",
            assessment,
        )

    return FindingDecision(finding, risk_level, "pass", "Finding is low risk for the current threshold.", assessment)


def _risk_level(finding: NormalizedFinding) -> str:
    if finding.secret_type == "private_key":
        return "critical"
    if finding.secret_type in {"aws_access_key", "github_token", "database_url"}:
        return "high"
    if finding.confidence >= 0.85:
        return "high"
    if finding.confidence >= 0.65:
        return "medium"
    return "low"


def _risk_value(risk_level: str) -> int:
    return RISK_ORDER.get(risk_level.lower(), RISK_ORDER["high"])
