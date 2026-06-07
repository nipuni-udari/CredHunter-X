from __future__ import annotations

from app.ci.decision import CIDecision, FindingDecision
from app.reporting.remediation import remediation_steps


def build_pr_comment(decision: CIDecision, max_findings: int = 10) -> str:
    visible = [item for item in decision.findings if item.action != "ignore"]
    lines = [
        "## CredHunter-X Report",
        "",
        f"Final action: `{decision.action}`",
        "",
        "| Count | Type |",
        "| --- | --- |",
        f"| {decision.finding_count} | Total findings |",
        f"| {decision.blocking_count} | Blocking |",
        f"| {decision.manual_review_count} | Manual review |",
        f"| {decision.warning_count} | Warnings |",
        f"| {decision.ignored_count} | Ignored |",
        "",
    ]

    if not visible:
        lines.append("No reportable findings.")
        return "\n".join(lines) + "\n"

    lines.extend(
        [
            "### Findings",
            "",
            "| Score | Risk | Action | Type | Location |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for item in visible[:max_findings]:
        finding = item.finding
        score = item.risk_score.score if item.risk_score else ""
        location = f"{finding.file_path}:{finding.line_number or 1}"
        lines.append(f"| {score} | {item.risk_level} | {item.action} | {finding.secret_type} | `{location}` |")

    if len(visible) > max_findings:
        lines.append("")
        lines.append(f"{len(visible) - max_findings} additional reportable findings are available in the JSON report.")

    top = visible[0]
    lines.extend(["", "### Recommended Next Steps", ""])
    for step in remediation_steps(top.finding.secret_type):
        lines.append(f"- {step}")

    lines.extend(["", "### Why This Was Reported", ""])
    lines.append(_finding_reason(top))
    return "\n".join(lines) + "\n"


def build_feedback_summary(findings: list[dict]) -> dict:
    summary = {
        "finding_count": len(findings),
        "suppressed_count": 0,
        "true_positive_count": 0,
        "false_positive_count": 0,
        "unreviewed_count": 0,
        "feedback": [],
    }

    for finding in findings:
        feedback = finding.get("feedback")
        if finding.get("suppressed"):
            summary["suppressed_count"] += 1
        if feedback and feedback.get("label") == "true_positive":
            summary["true_positive_count"] += 1
        elif feedback and feedback.get("label") == "false_positive":
            summary["false_positive_count"] += 1
        else:
            summary["unreviewed_count"] += 1

        if feedback or finding.get("suppression"):
            summary["feedback"].append(
                {
                    "finding_id": finding.get("finding_id"),
                    "file_path": finding.get("file_path"),
                    "line_number": finding.get("line_number"),
                    "action": finding.get("action"),
                    "risk_level": finding.get("risk_level"),
                    "feedback": feedback,
                    "suppression": finding.get("suppression"),
                }
            )

    return summary


def _finding_reason(item: FindingDecision) -> str:
    parts = [item.reason]
    if item.false_positive_assessment:
        reasons = item.false_positive_assessment.reasons
        if reasons:
            parts.append("Rule filter: " + " ".join(reasons))
    if item.llm_classification and item.llm_classification.used:
        parts.append(f"LLM: {item.llm_classification.classification} ({item.llm_classification.confidence:.2f}).")
    return " ".join(parts)
