from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class RawFinding:
    """Internal transient finding that may briefly contain a raw secret."""

    detector: str
    secret_type: str
    file_path: str
    line_number: int | None = None
    raw_secret: str | None = None
    matched_text: str | None = None
    confidence: float = 0.0
    entropy: float | None = None
    commit_sha: str | None = None
    rule_id: str | None = None
    description: str | None = None
    context_before: str | None = None
    context_after: str | None = None
    source: str = "unknown"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class NormalizedFinding:
    finding_id: str
    detector: str
    secret_type: str
    file_path: str
    line_number: int | None
    redacted_secret: str | None
    secret_hash: str | None
    confidence: float
    entropy: float | None
    commit_sha: str | None
    rule_id: str | None
    description: str | None
    context_before: str | None
    context_after: str | None
    source: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
