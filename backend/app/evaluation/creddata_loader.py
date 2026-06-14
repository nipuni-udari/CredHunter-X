from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from app.scanner.models import NormalizedFinding

DEFAULT_CRED_DATA_JSONL = Path(__file__).resolve().parents[2] / "Dataset" / "processed" / "creddata_python_eval.jsonl"
DEFAULT_CRED_DATA_SUMMARY = (
    Path(__file__).resolve().parents[2] / "Dataset" / "processed" / "creddata_python_eval.summary.json"
)

CATEGORY_TO_SECRET_TYPE = {
    "API": "generic_secret",
    "Auth": "oauth_token",
    "Key": "generic_secret",
    "Key:Secret": "generic_secret",
    "Password": "generic_high_entropy_secret",
    "Secret": "generic_secret",
    "Token": "oauth_token",
    "URL Credentials": "database_url",
    "UUID": "generic_secret",
}


def _secret_type_for_category(category: str) -> str:
    lowered = category.lower()
    # Private-key material must map to the protected type a real scanner would
    # assign; otherwise the deterministic filter could downgrade it.
    if "private key" in lowered or "pem" in lowered:
        return "private_key"
    if "aws" in lowered:
        return "aws_access_key"
    if "json web token" in lowered or category == "JWT":
        return "jwt"
    return CATEGORY_TO_SECRET_TYPE.get(category, "generic_secret")


@dataclass(slots=True)
class CredDataRecord:
    candidate_id: str
    file_path: str
    line_start: int | None
    category: str
    ground_truth: str
    ground_truth_raw: str
    redacted_secret: str | None
    confidence: float
    entropy: float | None
    commit_sha: str | None
    repo_url: str | None
    target_line_redacted: str | None
    code_context_redacted: str | None
    signals: dict
    raw: dict

    @classmethod
    def from_dict(cls, payload: dict) -> "CredDataRecord":
        features = payload.get("secret_features") or {}
        return cls(
            candidate_id=payload["candidate_id"],
            file_path=payload["file_path"],
            line_start=payload.get("line_start"),
            category=payload.get("category") or "Unknown",
            ground_truth=payload["ground_truth"],
            ground_truth_raw=payload.get("ground_truth_raw") or "",
            redacted_secret=payload.get("redacted_secret"),
            confidence=_confidence_for(payload["ground_truth"], features),
            entropy=features.get("entropy"),
            commit_sha=payload.get("commit_sha"),
            repo_url=payload.get("repo_url"),
            target_line_redacted=payload.get("target_line_redacted"),
            code_context_redacted=payload.get("code_context_redacted"),
            signals=payload.get("signals") or {},
            raw=payload,
        )

    def to_finding(self) -> NormalizedFinding:
        features = self.raw.get("secret_features") or {}
        return NormalizedFinding(
            finding_id=self.candidate_id,
            detector="creddata.labelled_candidate",
            secret_type=_secret_type_for_category(self.category),
            file_path=self.file_path,
            line_number=self.line_start,
            redacted_secret=self.redacted_secret,
            secret_hash=f"creddata-candidate:{self.candidate_id}",
            confidence=self.confidence,
            entropy=self.entropy,
            commit_sha=self.commit_sha,
            rule_id=f"creddata.{self.category.lower().replace(' ', '_').replace(':', '_')}",
            description=f"CredData labelled {self.category} candidate.",
            context_before=self.target_line_redacted,
            context_after=None,
            source="creddata",
            metadata={
                "source_dataset": "CredData",
                "repo_url": self.repo_url,
                "category": self.category,
                "ground_truth": self.ground_truth,
                "ground_truth_raw": self.ground_truth_raw,
                "signals": self.signals,
                "code_context_redacted": self.code_context_redacted,
                "secret_indicators": {
                    # Length of the located candidate value (None when CredData
                    # could not pin a value span on the flagged line).
                    "length": features.get("length"),
                    "has_value": bool(features.get("has_value_offsets")),
                    "in_comment": bool(self.signals.get("is_comment")),
                    "in_example_file": bool(self.signals.get("is_example_file")),
                    # Value-level structural signals are not derivable from the
                    # obfuscated CredData candidates; a real normalizer fills these.
                    "local_only_database_url": False,
                    "repeated_or_low_value": False,
                    "uuid_like": False,
                    "hash_like": False,
                    "has_private_key_marker": False,
                },
            },
        )


def load_creddata_records(
    path: str | Path = DEFAULT_CRED_DATA_JSONL,
    limit: int | None = None,
    labels: set[str] | None = None,
) -> list[CredDataRecord]:
    records: list[CredDataRecord] = []
    for payload in _iter_jsonl(path):
        if labels and payload.get("ground_truth") not in labels:
            continue
        records.append(CredDataRecord.from_dict(payload))
        if limit is not None and len(records) >= limit:
            break
    return records


def load_balanced_creddata_sample(
    path: str | Path = DEFAULT_CRED_DATA_JSONL,
    per_label: int = 5,
) -> list[CredDataRecord]:
    labels = {"true_secret": [], "false_positive": []}
    for payload in _iter_jsonl(path):
        label = payload.get("ground_truth")
        if label not in labels or len(labels[label]) >= per_label:
            continue
        labels[label].append(CredDataRecord.from_dict(payload))
        if all(len(items) >= per_label for items in labels.values()):
            break
    return labels["true_secret"] + labels["false_positive"]


def load_creddata_summary(path: str | Path = DEFAULT_CRED_DATA_SUMMARY) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def summarize_records(records: Iterable[CredDataRecord]) -> dict:
    summary = {"records": 0, "labels": {}, "categories": {}}
    for record in records:
        summary["records"] += 1
        summary["labels"][record.ground_truth] = summary["labels"].get(record.ground_truth, 0) + 1
        summary["categories"][record.category] = summary["categories"].get(record.category, 0) + 1
    return summary


def _iter_jsonl(path: str | Path):
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                yield json.loads(line)


def _confidence_for(label: str, features: dict) -> float:
    if label == "true_secret":
        return 0.85
    if features.get("has_value_offsets"):
        return 0.65
    return 0.5
