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
    "xxxxxxxx",
    "000000",
}

# Obvious non-production test values. Like placeholders, these should never reach
# the paid LLM stage; they are cheap, explainable local rejections.
TEST_VALUE_WORDS = {
    "test123",
    "fake-key",
    "fake_key",
    "fakekey",
    "fake-token",
    "fake_token",
    "faketoken",
    "sample-token",
    "sample_token",
    "sampletoken",
    "sample-key",
    "sample_key",
    "notarealsecret",
    "not_a_real_secret",
    "deadbeef",
}

# Findings that must never be downgraded by deterministic rules.
NON_DOWNGRADABLE_TYPES = {"private_key"}

# Only generic, format-less findings are eligible for entropy/length/no-value
# heuristics. Provider tokens (github/aws/jwt/oauth/database) have known shapes
# and are handled conservatively so real leaks are never silently dropped.
GENERIC_TYPES = {"generic_secret", "generic_high_entropy_secret"}


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
    is_generic = finding.secret_type in GENERIC_TYPES

    # Conservative safety: never let deterministic rules hide private keys.
    if finding.secret_type in NON_DOWNGRADABLE_TYPES:
        return FalsePositiveAssessment(
            classification="not_false_positive",
            ignored=False,
            reasons=["Finding type is not downgraded by rule-based false-positive filters."],
            signals=signals,
        )

    # 1. User-configured ignore paths (explicit intent, applies to every type).
    if signals["configured_ignored_path"]:
        return _ignore("false_positive", "File path matched configured ignore paths.", signals)

    # 1b. The value is read from the environment / a secret manager, not
    #     hard-coded (e.g. os.getenv("API_KEY")). This is the recommended safe
    #     pattern, so it is a false positive and must skip the paid LLM stage.
    if signals["env_reference"]:
        return _ignore("false_positive", "Value is read from the environment or a secret manager, not hard-coded.", signals)

    # 2. Literal placeholder / dummy / test value (applies to every type).
    if config.filters.allow_placeholders and signals["placeholder_value"]:
        return _ignore("false_positive", "Finding contains placeholder or dummy-value indicators.", signals)
    if config.filters.allow_placeholders and signals["test_value"]:
        return _ignore("false_positive", "Finding value is an obvious test/fake credential.", signals)

    # 2b. The value is already redacted (only stars or X characters); there is no
    #     real secret left to leak.
    if signals["redacted_only_value"]:
        return _ignore("likely_false_positive", "Finding value is already redacted (only mask characters).", signals)

    # 3. Local-only database URL.
    if signals["local_only_database_url"]:
        return _ignore("likely_false_positive", "Database URL appears to target a local-only service.", signals)

    # 4. Structurally non-secret values (repeated/sequential apply to every type;
    #    a real provider token is never "12341234" or an all-zero string).
    if signals["repeated_or_low_value"]:
        return _ignore("likely_false_positive", "Finding value is a repeated or sequential dummy string.", signals)

    # 5. UUIDs and digest-shaped hex strings are almost never live credentials.
    if is_generic and signals["uuid_like"]:
        return _ignore("likely_false_positive", "Generic finding value is a UUID, not a credential.", signals)
    if is_generic and signals["hash_like"]:
        return _ignore("likely_false_positive", "Generic finding value looks like a non-secret hash/digest.", signals)

    # 6a. No extractable secret value at all. A credential needs a value, so this
    #     is safe for every (non-private-key) type; real scanner findings always
    #     carry a value, so this only ever fires on value-less noise candidates.
    if config.filters.require_secret_value and signals["no_secret_value"]:
        return _ignore("likely_false_positive", "Finding has no extractable secret value.", signals)

    # 6b. Entropy/length heuristics stay generic-only: provider tokens can be
    #     short or low-entropy by format, so we must not downgrade them this way.
    if is_generic and signals["very_short_value"]:
        return _ignore("likely_false_positive", "Generic finding value is too short to be a real secret.", signals)
    if is_generic and signals["low_entropy_value"]:
        return _ignore("likely_false_positive", "Generic finding value entropy is below the real-secret range.", signals)

    # 7. Documentation / test / example paths. These legitimately contain real
    #    secrets (in CredData most true secrets live in test files), so we never
    #    auto-ignore on path alone: lower the risk to uncertain and let scoring /
    #    the LLM layer decide. Comment/example context adds weight but is not
    #    enough on its own to hide a real secret.
    if signals["doc_or_test_path"]:
        return FalsePositiveAssessment(
            classification="uncertain",
            ignored=False,
            risk_override="medium",
            reasons=["Finding appears in documentation, examples, tests, or fixtures."],
            signals=signals,
        )

    return FalsePositiveAssessment(
        classification="not_false_positive",
        ignored=False,
        reasons=["No deterministic false-positive rule matched."],
        signals=signals,
    )


def _ignore(classification: str, reason: str, signals: dict[str, bool]) -> FalsePositiveAssessment:
    return FalsePositiveAssessment(
        classification=classification,
        ignored=True,
        risk_override="low",
        reasons=[reason],
        signals=signals,
    )


def _signals(finding: NormalizedFinding, config: CredHunterConfig) -> dict[str, bool]:
    indicators = finding.metadata.get("secret_indicators", {})
    context_signals = finding.metadata.get("signals", {})
    text = _safe_text(finding)
    length = _value_length(finding, indicators)
    entropy = finding.entropy
    return {
        "configured_ignored_path": _is_ignored_path(finding.file_path, config.filters.ignore_paths),
        "doc_or_test_path": _is_doc_or_test_path(finding.file_path),
        "in_comment": bool(indicators.get("in_comment") or context_signals.get("is_comment")),
        "in_example_file": bool(indicators.get("in_example_file") or context_signals.get("is_example_file")),
        "env_reference": bool(context_signals.get("env_reference")),
        "placeholder_value": bool(indicators.get("placeholder")) or _contains_placeholder(text),
        "test_value": bool(indicators.get("test_value")) or _contains_test_value(text),
        "redacted_only_value": _is_redacted_only(finding.redacted_secret),
        "local_only_database_url": bool(indicators.get("local_only_database_url")),
        "repeated_or_low_value": bool(indicators.get("repeated_or_low_value")) or _contains_repeated_dummy(text),
        "uuid_like": bool(indicators.get("uuid_like")),
        "hash_like": bool(indicators.get("hash_like")),
        "no_secret_value": _has_no_value(finding, indicators),
        "very_short_value": length is not None and length < config.filters.min_secret_length,
        "low_entropy_value": entropy is not None and entropy < config.filters.min_entropy,
    }


def _value_length(finding: NormalizedFinding, indicators: dict) -> int | None:
    length = indicators.get("length")
    if isinstance(length, int):
        return length
    if finding.redacted_secret:
        return None
    return None


def _has_no_value(finding: NormalizedFinding, indicators: dict) -> bool:
    if "has_value" in indicators:
        return not indicators["has_value"]
    return finding.entropy is None and not finding.redacted_secret


def _safe_text(finding: NormalizedFinding) -> str:
    # Deliberately excludes surrounding code context: a placeholder verdict must
    # describe the secret value itself, not a code line that merely mentions
    # words like "example" (that was a source of real-secret over-suppression).
    parts = [
        finding.redacted_secret or "",
        finding.description or "",
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


def _contains_test_value(text: str) -> bool:
    return any(word in text for word in TEST_VALUE_WORDS)


def _is_redacted_only(redacted_secret: str | None) -> bool:
    if not redacted_secret:
        return False
    stripped = redacted_secret.strip()
    if not stripped:
        return False
    # A value made up entirely of mask characters (****, XXXX, ••••) has no
    # recoverable secret left in it.
    return all(char in "*xX•·#" for char in stripped)


def _contains_repeated_dummy(text: str) -> bool:
    return "****0000" in text or "0000****" in text or "****abcd" in text or "abcd****" in text
