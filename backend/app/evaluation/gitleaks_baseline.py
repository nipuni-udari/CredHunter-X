from __future__ import annotations

import json
from pathlib import Path

from app.evaluation.creddata_loader import CredDataRecord


def match_gitleaks_report_to_creddata(report_path: str | Path, records: list[CredDataRecord]) -> set[str]:
    findings = _load_gitleaks_json(report_path)
    index = _index_records(records)
    matched_ids: set[str] = set()

    for finding in findings:
        file_path = _normalize_path(str(_get(finding, "File", "file", "uri", default="")))
        line_number = _to_int(_get(finding, "StartLine", "start_line", "line", default=None))
        if not file_path or line_number is None:
            continue

        for key in _candidate_keys(file_path, line_number):
            if key in index:
                matched_ids.update(index[key])

    return matched_ids


def _load_gitleaks_json(report_path: str | Path) -> list[dict]:
    payload = json.loads(Path(report_path).read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and "runs" in payload:
        return _from_sarif(payload)
    raise ValueError("Unsupported Gitleaks report format for baseline matching.")


def _from_sarif(payload: dict) -> list[dict]:
    findings = []
    for run in payload.get("runs", []):
        for result in run.get("results", []):
            location = (result.get("locations") or [{}])[0]
            physical = location.get("physicalLocation", {})
            artifact = physical.get("artifactLocation", {})
            region = physical.get("region", {})
            findings.append(
                {
                    "File": artifact.get("uri"),
                    "StartLine": region.get("startLine"),
                }
            )
    return findings


def _index_records(records: list[CredDataRecord]) -> dict[tuple[str, int], list[str]]:
    index: dict[tuple[str, int], list[str]] = {}
    for record in records:
        if record.line_start is None:
            continue
        key = (_normalize_path(record.file_path), record.line_start)
        index.setdefault(key, []).append(record.candidate_id)
    return index


def _candidate_keys(file_path: str, line_number: int):
    normalized = _normalize_path(file_path)
    yield (normalized, line_number)
    marker = "dataset/data/"
    if marker in normalized:
        yield (normalized[normalized.index(marker) :], line_number)
    marker = "data/"
    if marker in normalized:
        yield (normalized[normalized.index(marker) :], line_number)


def _normalize_path(value: str) -> str:
    return value.replace("\\", "/").lstrip("./").lower()


def _get(payload: dict, *keys: str, default=None):
    for key in keys:
        if key in payload:
            return payload[key]
    return default


def _to_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
