"""Merge and deduplicate candidates from multiple generators.

Gitleaks and the Python extractor frequently surface the *same* leak (a token on
a given line in a ``.py`` file). This stage combines both lists into one, drops
duplicates, and -- when two generators agree on a location -- keeps the stronger
finding while recording that more than one detector saw it.

Deduplication uses location plus secret identity, not ``secret_type``. Different
detectors often name the same value differently (for example ``github_token`` vs
``generic_secret``), so type labels are preserved as merge metadata instead.
Gitleaks is treated as the authoritative detector on a tie because its findings
carry provider rule IDs and commit metadata.
"""

from __future__ import annotations

import hashlib
from typing import Any

from .models import NormalizedFinding

# Detector priority when two candidates collide on the dedupe key. Higher wins.
_SOURCE_PRIORITY = {
    "gitleaks_json": 3,
    "gitleaks_sarif": 3,
    "source_scanner": 2,
    "python_extractor": 1,
}


def merge_and_dedupe(*candidate_lists: list[NormalizedFinding]) -> list[NormalizedFinding]:
    """Merge candidate lists, keeping the strongest finding per location.

    Order is preserved by first appearance so Gitleaks findings (passed first)
    lead the report. Merge metadata records every detector/source/type/rule that
    independently confirmed the same secret.
    """

    merged: dict[tuple, NormalizedFinding] = {}
    order: list[tuple] = []

    for candidates in candidate_lists:
        for finding in candidates:
            key = _dedupe_key(finding)
            existing = merged.get(key)
            if existing is None:
                merged[key] = finding
                order.append(key)
                continue
            merged[key] = _reconcile(existing, finding)

    return [merged[key] for key in order]


def _dedupe_key(finding: NormalizedFinding) -> tuple:
    return (
        _normalize_path(finding.file_path),
        finding.line_number,
        _secret_identity(finding),
    )


def _reconcile(existing: NormalizedFinding, incoming: NormalizedFinding) -> NormalizedFinding:
    """Return the finding to keep, annotating it with the other detector."""

    keep, drop = (existing, incoming)
    if _priority(incoming) > _priority(existing):
        keep, drop = (incoming, existing)
    elif _priority(incoming) == _priority(existing) and incoming.confidence > existing.confidence:
        keep, drop = (incoming, existing)

    keep.confidence = max(existing.confidence, incoming.confidence)
    _merge_metadata(keep, drop)
    return keep


def _priority(finding: NormalizedFinding) -> int:
    return _SOURCE_PRIORITY.get(finding.source, 0)


def _normalize_path(file_path: str) -> str:
    return (file_path or "").replace("\\", "/")


def _secret_identity(finding: NormalizedFinding) -> tuple[str, str]:
    if finding.secret_hash:
        return ("secret_hash", finding.secret_hash)
    if finding.redacted_secret:
        return ("redacted_secret", finding.redacted_secret)

    line = finding.metadata.get("target_line") or finding.metadata.get("masked_target_line")
    if isinstance(line, str) and line.strip():
        digest = hashlib.sha256(line.strip().encode("utf-8")).hexdigest()
        return ("target_line_hash", digest)

    fallback = "|".join(
        str(value or "")
        for value in (finding.secret_type, finding.rule_id, finding.detector)
    )
    return ("fallback", fallback)


def _merge_metadata(keep: NormalizedFinding, drop: NormalizedFinding) -> None:
    detectors = _merged_values(keep, drop, "detected_by", "detector")
    sources = _merged_values(keep, drop, "detected_sources", "source")
    secret_types = _merged_values(keep, drop, "merged_secret_types", "secret_type")
    rule_ids = _merged_values(keep, drop, "merged_rule_ids", "rule_id")

    keep.metadata["detected_by"] = sorted(detectors)
    keep.metadata["detected_sources"] = sorted(sources)
    keep.metadata["merged_secret_types"] = sorted(secret_types)
    if rule_ids:
        keep.metadata["merged_rule_ids"] = sorted(rule_ids)

    also = detectors - {keep.detector}
    if also:
        keep.metadata["also_detected_by"] = sorted(also)


def _merged_values(
    keep: NormalizedFinding,
    drop: NormalizedFinding,
    metadata_key: str,
    attr_name: str,
) -> set[str]:
    values = set(_metadata_list(keep.metadata.get(metadata_key)))
    values.update(_metadata_list(drop.metadata.get(metadata_key)))
    for finding in (keep, drop):
        value = getattr(finding, attr_name)
        if value:
            values.add(str(value))
    return values


def _metadata_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item]
    return [str(value)]
