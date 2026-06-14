from __future__ import annotations

import json
from pathlib import Path

from app.reporting.markdown import build_pr_comment, redacted_cell

from .decision import CIDecision


def write_json_report(decision: CIDecision, path: str | Path) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(decision.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_sarif_report(decision: CIDecision, path: str | Path) -> None:
    payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CredHunter-X",
                        "informationUri": "https://github.com/",
                        "rules": _sarif_rules(decision),
                    }
                },
                "results": [_sarif_result(item) for item in decision.findings if item.action != "ignore"],
            }
        ],
    }
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_github_summary(decision: CIDecision, path: str | Path) -> None:
    lines = [
        "# CredHunter-X Scan Summary",
        "",
        f"- Final action: `{decision.action}`",
        f"- Total findings: `{decision.finding_count}`",
        f"- Blocking findings: `{decision.blocking_count}`",
        f"- Manual review findings: `{decision.manual_review_count}`",
        f"- Warning findings: `{decision.warning_count}`",
        f"- Ignored findings: `{decision.ignored_count}`",
        "",
    ]

    visible = [item for item in decision.findings if item.action != "ignore"]
    if visible:
        lines.extend(
            [
                "| Score | Risk | Action | Type | Secret | Location |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for item in visible:
            finding = item.finding
            location = f"{finding.file_path}:{finding.line_number or 1}"
            score = item.risk_score.score if item.risk_score else ""
            secret = redacted_cell(finding)
            lines.append(
                f"| {score} | {item.risk_level} | {item.action} | {finding.secret_type} | {secret} | `{location}` |"
            )
    else:
        lines.append("No reportable findings.")

    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_pr_comment(decision: CIDecision, path: str | Path) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(build_pr_comment(decision), encoding="utf-8")


def _sarif_rules(decision: CIDecision) -> list[dict]:
    rules = {}
    for item in decision.findings:
        rule_id = item.finding.rule_id or item.finding.detector
        rules[rule_id] = {
            "id": rule_id,
            "name": item.finding.secret_type,
            "shortDescription": {"text": item.finding.description or item.finding.secret_type},
            "properties": {"security-severity": _severity(item.risk_level)},
        }
    return list(rules.values())


def _sarif_result(item) -> dict:
    finding = item.finding
    rule_id = finding.rule_id or finding.detector
    return {
        "ruleId": rule_id,
        "level": _sarif_level(item.risk_level),
        "message": {"text": f"{finding.secret_type} finding classified as {item.risk_level}: {item.reason}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file_path},
                    "region": {"startLine": finding.line_number or 1},
                }
            }
        ],
        "properties": {
            "credhunter_action": item.action,
            "credhunter_finding_id": finding.finding_id,
            "credhunter_risk_score": item.risk_score.score if item.risk_score else None,
            "redacted_secret": finding.redacted_secret,
        },
    }


def _sarif_level(risk_level: str) -> str:
    if risk_level in {"critical", "high"}:
        return "error"
    if risk_level == "medium":
        return "warning"
    return "note"


def _severity(risk_level: str) -> str:
    return {
        "critical": "9.5",
        "high": "8.0",
        "medium": "5.0",
        "low": "2.0",
    }.get(risk_level, "5.0")
