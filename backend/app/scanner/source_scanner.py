from __future__ import annotations

import re
from pathlib import Path

from .entropy import shannon_entropy
from .models import NormalizedFinding, RawFinding
from .normalizer import normalize_finding

MAX_FILE_BYTES = 1_000_000
SKIPPED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"}

PATTERNS: list[tuple[str, str, re.Pattern[str], float]] = [
    ("regex.aws_access_key", "aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), 0.9),
    ("regex.github_token", "github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs)_[A-Za-z0-9_]{20,}\b"), 0.9),
    ("regex.github_pat", "github_token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b"), 0.9),
    ("regex.private_key", "private_key", re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |OPENSSH |EC )?PRIVATE KEY-----"), 0.98),
    ("regex.database_url", "database_url", re.compile(r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://[^\s'\"<>]+", re.IGNORECASE), 0.82),
    ("regex.jwt", "jwt", re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"), 0.72),
]

ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(?:api[_-]?key|secret|token|password|client[_-]?secret)\b\s*[:=]\s*[\"']?([A-Za-z0-9_./+=-]{20,})[\"']?"
)


def scan_path(path: str | Path) -> list[NormalizedFinding]:
    root = Path(path)
    findings: list[NormalizedFinding] = []

    files = [root] if root.is_file() else _iter_files(root)
    for file_path in files:
        findings.extend(_scan_file(file_path, root if root.is_dir() else file_path.parent))

    return findings


def _iter_files(root: Path):
    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue
        if any(part in SKIPPED_DIRS for part in file_path.parts):
            continue
        yield file_path


def _scan_file(file_path: Path, root: Path) -> list[NormalizedFinding]:
    if file_path.stat().st_size > MAX_FILE_BYTES:
        return []

    try:
        content = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []

    relative_path = str(file_path.relative_to(root)) if file_path != root else str(file_path)
    findings: list[NormalizedFinding] = []

    for detector, secret_type, pattern, confidence in PATTERNS:
        for match in pattern.finditer(content):
            raw_secret = match.group(0)
            findings.append(
                normalize_finding(
                    RawFinding(
                        detector=detector,
                        secret_type=secret_type,
                        file_path=relative_path,
                        line_number=_line_number(content, match.start()),
                        raw_secret=raw_secret,
                        matched_text=raw_secret,
                        confidence=confidence,
                        entropy=shannon_entropy(raw_secret),
                        source="source_scanner",
                    )
                )
            )

    for match in ASSIGNMENT_PATTERN.finditer(content):
        raw_secret = match.group(1)
        entropy = shannon_entropy(raw_secret)
        if entropy < 3.8:
            continue
        findings.append(
            normalize_finding(
                RawFinding(
                    detector="entropy.assignment",
                    secret_type="generic_high_entropy_secret",
                    file_path=relative_path,
                    line_number=_line_number(content, match.start(1)),
                    raw_secret=raw_secret,
                    matched_text=match.group(0),
                    confidence=0.65,
                    entropy=entropy,
                    source="source_scanner",
                )
            )
        )

    return findings


def _line_number(content: str, index: int) -> int:
    return content.count("\n", 0, index) + 1
