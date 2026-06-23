from __future__ import annotations

from app.ci.decision import CIDecision, FindingDecision
from app.scanner.models import NormalizedFinding


def redacted_cell(finding: NormalizedFinding) -> str:
    """Markdown-table cell for a redacted secret value (never the raw secret)."""

    value = (finding.redacted_secret or "").strip()
    if not value:
        return "—"
    # Keep the cell on one line and table-safe.
    value = value.replace("`", "").replace("|", "\\|").replace("\n", " ")
    if len(value) > 48:
        value = value[:45] + "…"
    return f"`{value}`"


def llm_engine_banner(decision: CIDecision) -> str:
    """One-line human summary of whether the LLM ran or the pipeline fell back."""

    status = decision.llm_status or {}
    mode = status.get("mode", "deterministic")
    if mode == "llm":
        active = [name for name, state in status.get("stages", {}).items() if state == "active"]
        stages = ", ".join(active) if active else "classify"
        return f"Engine: 🤖 LLM-assisted — model `{status.get('model', 'n/a')}`, stages: {stages}."
    if mode == "fallback":
        return f"Engine: ⚠️ Deterministic fallback — LLM not used ({status.get('reason', 'unknown')})."
    return "Engine: 🛡️ Deterministic only — LLM disabled in configuration."


def build_pr_comment(decision: CIDecision, max_findings: int = 10) -> str:
    visible = [item for item in decision.findings if item.action != "ignore"]
    lines = [
        "## CredHunter-X Report",
        "",
        llm_engine_banner(decision),
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
            "| Score | Risk | Action | Type | Secret | Location |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for item in visible[:max_findings]:
        finding = item.finding
        score = item.risk_score.score if item.risk_score else ""
        location = f"{finding.file_path}:{finding.line_number or 1}"
        secret = redacted_cell(finding)
        lines.append(
            f"| {score} | {item.risk_level} | {item.action} | {finding.secret_type} | {secret} | `{location}` |"
        )

    if len(visible) > max_findings:
        lines.append("")
        lines.append(f"{len(visible) - max_findings} additional reportable findings are available in the JSON report.")

    top = visible[0]
    lines.extend(["", "### Recommended Next Steps", ""])
    for step in top.remediation():
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
    parts = [item.explanation()]
    if item.false_positive_assessment:
        reasons = item.false_positive_assessment.reasons
        if reasons:
            parts.append("Rule filter: " + " ".join(reasons))
    if item.llm_classification and item.llm_classification.used:
        parts.append(f"LLM: {item.llm_classification.classification} ({item.llm_classification.confidence:.2f}).")
    return " ".join(parts)
