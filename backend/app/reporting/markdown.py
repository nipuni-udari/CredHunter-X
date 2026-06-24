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


_SECRET_TITLES = {
    "private_key": "Hardcoded Private Key",
    "aws_access_key": "Hardcoded AWS Access Key",
    "github_token": "Hardcoded GitHub Token",
    "google_api_key": "Hardcoded Google API Key",
    "stripe_api_key": "Hardcoded Stripe API Key",
    "slack_token": "Hardcoded Slack Token",
    "database_url": "Hardcoded Database Connection String",
    "oauth_token": "Hardcoded OAuth / Bearer Token",
    "jwt": "Hardcoded JWT",
    "generic_secret": "Hardcoded Secret",
    "generic_high_entropy_secret": "Hardcoded High-Entropy Secret",
}

_SAFE_PATTERNS = {
    "database_url": 'DATABASE_URL = os.getenv("DATABASE_URL")',
    "github_token": 'GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")',
    "aws_access_key": 'AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")',
    "jwt": 'JWT = os.getenv("JWT")',
    "oauth_token": 'ACCESS_TOKEN = os.getenv("ACCESS_TOKEN")',
}
_DEFAULT_SAFE_PATTERN = 'API_KEY = os.getenv("API_KEY")'

_RISK_HEADINGS = {
    "critical": "Critical Risk",
    "high": "High Risk",
    "medium": "Medium Risk",
    "low": "Low Risk",
}


def build_markdown_summary(decision: CIDecision) -> str:
    """Developer-friendly Markdown report: one remediation card per finding.

    Unlike the terse PR-comment table, this is meant to be read and acted on: it
    shows location, classification, confidence, why the finding matters, the
    concrete remediation steps, and a safe code pattern -- always with the secret
    masked, never the raw value.
    """

    lines = [
        "# CredHunter-X Developer Report",
        "",
        llm_engine_banner(decision),
        "",
        f"**Final action:** `{decision.action}`  ",
        f"**Findings:** {decision.finding_count} total · "
        f"{decision.blocking_count} blocking · "
        f"{decision.manual_review_count} manual review · "
        f"{decision.warning_count} warning · "
        f"{decision.ignored_count} ignored",
        "",
    ]

    visible = [item for item in decision.findings if item.action != "ignore"]
    visible.sort(key=lambda item: item.risk_score.score if item.risk_score else 0, reverse=True)

    if not visible:
        lines.append("No reportable findings. ✅")
        return "\n".join(lines) + "\n"

    lines.append("---")
    for item in visible:
        lines.extend(_remediation_card(item))
        lines.append("---")

    return "\n".join(lines) + "\n"


def _remediation_card(item: FindingDecision) -> list[str]:
    finding = item.finding
    heading = _RISK_HEADINGS.get(item.risk_level, item.risk_level.title())
    title = _SECRET_TITLES.get(finding.secret_type, "Potential Secret")
    location = f"{finding.file_path}:{finding.line_number or 1}"
    classification, confidence = _classification_label(item)

    lines = [
        "",
        f"### {heading}: {title}",
        "",
        f"- **File:** `{location}`",
        f"- **Type:** `{finding.secret_type}`",
        f"- **Action:** `{item.action}`",
        f"- **Classification:** {classification}",
        f"- **Confidence:** {confidence}",
        f"- **Secret (masked):** {redacted_cell(finding)}",
        "",
        "**Why this matters:**",
        "",
        item.explanation(),
        "",
        "**Recommended fix:**",
        "",
    ]
    for index, step in enumerate(item.remediation(), start=1):
        lines.append(f"{index}. {step}")
    lines.extend(
        [
            "",
            "**Safe code pattern:**",
            "",
            "```python",
            _SAFE_PATTERNS.get(finding.secret_type, _DEFAULT_SAFE_PATTERN),
            "```",
        ]
    )
    return lines


def _classification_label(item: FindingDecision) -> tuple[str, str]:
    if item.llm_classification and item.llm_classification.used:
        return (
            item.llm_classification.classification,
            f"{item.llm_classification.confidence:.2f}",
        )
    if item.false_positive_assessment:
        return (item.false_positive_assessment.classification, "n/a (rule-based)")
    return ("uncertain", "n/a")


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
