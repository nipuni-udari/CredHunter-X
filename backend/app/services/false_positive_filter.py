from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch

from app.ci.config import CredHunterConfig
from app.scanner.models import NormalizedFinding


DOC_TEST_PATH_PARTS = {
    "doc",
    "docs",
    "documentation",
    "example",
    "examples",
    "fixture",
    "fixtures",
    "mock",
    "mocks",
    "sample",
    "samples",
    "test",
    "tests",
}

PLACEHOLDER_WORDS = {
    "example",
    "dummy",
    "sample",
    "changeme",
    "change_me",
    "placeholder",
    "your_api_key",
    "your-api-key",
    "your_api_key_here",
    "your-token",
    "your_token",
    "replace_me",
    "replace-me",
    "000000",
}

NON_DOWNGRADABLE_TYPES = {"private_key"}


@dataclass(slots=True)
class FalsePositiveAssessment:
    classification: str
    ignored: bool = False
    risk_override: str | None = None
    reasons: list[str] = field(default_factory=list)
    signals: dict[str, bool] = field(default_factory=dict)

    def to_metadata(self) -> dict:
        return {
            "classification": self.classification,
            "ignored": self.ignored,
            "risk_override": self.risk_override,
            "reasons": self.reasons,
            "signals": self.signals,
        }


def assess_false_positive(finding: NormalizedFinding, config: CredHunterConfig) -> FalsePositiveAssessment:
    signals = _signals(finding, config)
    reasons: list[str] = []

    if finding.secret_type in NON_DOWNGRADABLE_TYPES:
        return FalsePositiveAssessment(
            classification="not_false_positive",
            ignored=False,
            reasons=["Finding type is not downgraded by rule-based false-positive filters."],
            signals=signals,
        )

    if signals["configured_ignored_path"]:
        reasons.append("File path matched configured ignore paths.")
        return FalsePositiveAssessment("false_positive", True, "low", reasons, signals)

    if config.filters.allow_placeholders and signals["placeholder_value"]:
        reasons.append("Finding contains placeholder or dummy-value indicators.")
        return FalsePositiveAssessment("false_positive", True, "low", reasons, signals)

    if signals["local_only_database_url"]:
        reasons.append("Database URL appears to target a local-only service.")
        return FalsePositiveAssessment("likely_false_positive", True, "low", reasons, signals)

    if signals["doc_or_test_path"] and finding.secret_type == "generic_high_entropy_secret":
        reasons.append("Generic high-entropy finding appears in documentation, examples, tests, or fixtures.")
        return FalsePositiveAssessment("likely_false_positive", True, "low", reasons, signals)

    if signals["doc_or_test_path"]:
        reasons.append("Finding appears in documentation, examples, tests, or fixtures.")
        return FalsePositiveAssessment("uncertain", False, "medium", reasons, signals)

    if signals["repeated_or_low_value"]:
        reasons.append("Finding value has repeated or low-value dummy indicators.")
        return FalsePositiveAssessment("likely_false_positive", True, "low", reasons, signals)

    return FalsePositiveAssessment(
        classification="not_false_positive",
        ignored=False,
        reasons=["No deterministic false-positive rule matched."],
        signals=signals,
    )


def _signals(finding: NormalizedFinding, config: CredHunterConfig) -> dict[str, bool]:
    indicators = finding.metadata.get("secret_indicators", {})
    text = _safe_text(finding)
    return {
        "configured_ignored_path": _is_ignored_path(finding.file_path, config.filters.ignore_paths),
        "doc_or_test_path": _is_doc_or_test_path(finding.file_path),
        "placeholder_value": bool(indicators.get("placeholder")) or _contains_placeholder(text),
        "local_only_database_url": bool(indicators.get("local_only_database_url")),
        "repeated_or_low_value": bool(indicators.get("repeated_or_low_value")) or _contains_repeated_dummy(text),
    }


def _safe_text(finding: NormalizedFinding) -> str:
    parts = [
        finding.file_path,
        finding.redacted_secret or "",
        finding.description or "",
        finding.context_before or "",
        finding.context_after or "",
        str(finding.metadata.get("message") or ""),
    ]
    return " ".join(parts).lower()


def _is_ignored_path(file_path: str, ignore_paths: list[str]) -> bool:
    normalized = file_path.replace("\\", "/")
    return any(fnmatch(normalized, pattern.replace("\\", "/")) for pattern in ignore_paths)


def _is_doc_or_test_path(file_path: str) -> bool:
    parts = {part.lower() for part in file_path.replace("\\", "/").split("/")}
    if parts & DOC_TEST_PATH_PARTS:
        return True
    lowered = file_path.lower()
    return lowered.endswith((".md", ".rst", ".adoc"))


def _contains_placeholder(text: str) -> bool:
    return any(word in text for word in PLACEHOLDER_WORDS)


def _contains_repeated_dummy(text: str) -> bool:
    return "****0000" in text or "0000****" in text or "****abcd" in text or "abcd****" in text
