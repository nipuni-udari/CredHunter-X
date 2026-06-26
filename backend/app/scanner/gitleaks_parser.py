from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import NormalizedFinding, RawFinding
from .normalizer import normalize_finding


def parse_gitleaks_report(path: str | Path) -> list[NormalizedFinding]:
    report_path = Path(path)
    payload = json.loads(report_path.read_text(encoding="utf-8"))

    if isinstance(payload, list):
        raw_findings = [_from_gitleaks_json(item) for item in payload]
    elif isinstance(payload, dict) and "runs" in payload:
        raw_findings = list(_from_sarif(payload))
    else:
        raise ValueError("Unsupported Gitleaks report format. Expected JSON array or SARIF object.")

    return [normalize_finding(finding) for finding in raw_findings]


def _from_gitleaks_json(item: dict[str, Any]) -> RawFinding:
    rule_id = _get(item, "RuleID", "rule_id", "ruleId") or "gitleaks.unknown"
    secret = _get(item, "Secret", "secret")
    matched_text = _get(item, "Match", "match")

    return RawFinding(
        detector="gitleaks",
        secret_type=_secret_type_from_rule(str(rule_id)),
        file_path=str(_get(item, "File", "file", "file_path") or "unknown"),
        line_number=_to_int(_get(item, "StartLine", "start_line", "line")),
        raw_secret=str(secret) if secret is not None else None,
        matched_text=str(matched_text) if matched_text is not None else None,
        confidence=0.85,
        entropy=_to_float(_get(item, "Entropy", "entropy")),
        commit_sha=_get(item, "Commit", "commit", "commit_sha"),
        rule_id=str(rule_id),
        description=_get(item, "Description", "description"),
        source="gitleaks_json",
        metadata={
            "author": _get(item, "Author", "author"),
            "email": _get(item, "Email", "email"),
            "date": _get(item, "Date", "date"),
            "message": _get(item, "Message", "message"),
            "fingerprint": _get(item, "Fingerprint", "fingerprint"),
            "tags": _get(item, "Tags", "tags"),
        },
    )


def _from_sarif(payload: dict[str, Any]):
    for run in payload.get("runs", []):
        rules = {
            rule.get("id"): rule
            for rule in run.get("tool", {}).get("driver", {}).get("rules", [])
            if isinstance(rule, dict)
        }
        for result in run.get("results", []):
            rule_id = result.get("ruleId") or "gitleaks.unknown"
            rule = rules.get(rule_id, {})
            location = _first(result.get("locations", [])) or {}
            physical = location.get("physicalLocation", {})
            artifact = physical.get("artifactLocation", {})
            region = physical.get("region", {})
            properties = result.get("properties", {})

            secret = properties.get("secret") or properties.get("partialFingerprints", {}).get("secret")

            yield RawFinding(
                detector="gitleaks",
                secret_type=_secret_type_from_rule(str(rule_id)),
                file_path=str(artifact.get("uri") or "unknown"),
                line_number=_to_int(region.get("startLine")),
                raw_secret=str(secret) if secret else None,
                confidence=0.8,
                entropy=_to_float(properties.get("entropy")),
                rule_id=str(rule_id),
                description=_message_text(result) or rule.get("shortDescription", {}).get("text"),
                source="gitleaks_sarif",
                metadata={
                    "level": result.get("level"),
                    "fingerprints": result.get("fingerprints"),
                    "partial_fingerprints": result.get("partialFingerprints"),
                },
            )


def _secret_type_from_rule(rule_id: str) -> str:
    lowered = rule_id.lower()
    if "aws" in lowered:
        return "aws_access_key_id"
    if "github" in lowered:
        return "github_token"
    if "jwt" in lowered:
        return "jwt"
    if "private-key" in lowered or "private_key" in lowered or "rsa" in lowered:
        return "private_key"
    if "mongodb" in lowered or "postgres" in lowered or "mysql" in lowered or "database" in lowered:
        return "database_url"
    if "oauth" in lowered:
        return "oauth_token"
    return "generic_secret"


def _get(item: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in item:
            return item[key]
    return None


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _to_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _first(values: list[Any]) -> Any:
    return values[0] if values else None


def _message_text(result: dict[str, Any]) -> str | None:
    message = result.get("message")
    if isinstance(message, dict):
        return message.get("text")
    return None
