"""Merge and deduplicate candidates from multiple generators.

Gitleaks and the Python extractor frequently surface the *same* leak (a token on
a given line in a ``.py`` file). This stage combines both lists into one, drops
duplicates, and -- when two generators agree on a location -- keeps the stronger
finding while recording that more than one detector saw it.

Deduplication key, per the design: ``(file_path, line_number, secret_type,
masked secret preview)``. Gitleaks is treated as the authoritative detector on a
tie because its findings carry provider rule IDs and commit metadata.
"""

from __future__ import annotations

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
    lead the report; an ``also_detected_by`` metadata note is added whenever a
    second generator independently confirms the same location.
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
        finding.secret_type,
        finding.redacted_secret,
    )


def _reconcile(existing: NormalizedFinding, incoming: NormalizedFinding) -> NormalizedFinding:
    """Return the finding to keep, annotating it with the other detector."""

    keep, drop = (existing, incoming)
    if _priority(incoming) > _priority(existing):
        keep, drop = (incoming, existing)
    elif _priority(incoming) == _priority(existing) and incoming.confidence > existing.confidence:
        keep, drop = (incoming, existing)

    also = set(keep.metadata.get("also_detected_by") or [])
    also.add(drop.detector)
    also.discard(keep.detector)
    if also:
        keep.metadata["also_detected_by"] = sorted(also)
    return keep


def _priority(finding: NormalizedFinding) -> int:
    return _SOURCE_PRIORITY.get(finding.source, 0)


def _normalize_path(file_path: str) -> str:
    return (file_path or "").replace("\\", "/")
