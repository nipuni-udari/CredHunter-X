"""Python-specific candidate extractor.

Gitleaks is regex-driven and generic; it misses Python idioms where a credential
is assigned to a well-named variable or dict key with a value that has no
provider-specific shape (a bare ``password = "hunter2longvalue"``). This module
walks the Python AST (with a small regex fallback for headers and connection
strings) to surface those candidates, while deliberately *ignoring* the safe
pattern of reading a value from the environment (``os.getenv("API_KEY")``).

Only string **literals assigned directly in code** become candidates. Calls,
f-strings interpolating env reads, and ``os.environ`` lookups are skipped, so the
extractor adds signal without flooding the pipeline with safe env references.
"""

from __future__ import annotations

import ast
import re
import warnings
from pathlib import Path

from .entropy import shannon_entropy
from .models import NormalizedFinding, RawFinding
from .normalizer import normalize_finding

MAX_FILE_BYTES = 1_000_000
SKIPPED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"}

# Credential-ish identifier keywords for assignment targets and dict keys.
CREDENTIAL_KEYWORDS = (
    "api_key",
    "apikey",
    "secret",
    "client_secret",
    "clientsecret",
    "access_token",
    "refresh_token",
    "token",
    "password",
    "passwd",
    "authorization",
    "auth_token",
    "private_key",
)

MIN_VALUE_LENGTH = 8

_CONNECTION_STRING_RE = re.compile(
    r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^\s'\"<>]+",
    re.IGNORECASE,
)
# A connection string only counts as a candidate when it carries a `user:pass@`.
_CONNECTION_WITH_CREDS_RE = re.compile(r"://[^/\s:@]+:[^/\s:@]+@")
_BEARER_RE = re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-.=]{12,}")


def extract_python_candidates(path: str | Path) -> list[NormalizedFinding]:
    root = Path(path)
    findings: list[NormalizedFinding] = []

    files = [root] if root.is_file() else _iter_python_files(root)
    for file_path in files:
        relative = (
            str(file_path.relative_to(root)) if root.is_dir() else str(file_path)
        )
        findings.extend(_scan_file(file_path, relative))

    return findings


def _iter_python_files(root: Path):
    for file_path in root.rglob("*.py"):
        if not file_path.is_file():
            continue
        if any(part in SKIPPED_DIRS for part in file_path.parts):
            continue
        yield file_path


def _scan_file(file_path: Path, relative_path: str) -> list[NormalizedFinding]:
    try:
        if file_path.stat().st_size > MAX_FILE_BYTES:
            return []
        source = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []

    raw_candidates: list[RawFinding] = []
    seen: set[tuple[int, str]] = set()

    try:
        # Parsing arbitrary scanned source can emit Syntax/Deprecation warnings
        # about its own string-literal escapes; silence them -- we only care
        # about the resulting AST, not the scanned file's lint cleanliness.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(source)
    except (SyntaxError, ValueError):
        tree = None

    if tree is not None:
        for candidate in _walk_ast(tree, relative_path):
            key = (candidate.line_number or 0, candidate.raw_secret or "")
            if key in seen:
                continue
            seen.add(key)
            raw_candidates.append(candidate)

    for candidate in _regex_fallback(source, relative_path):
        key = (candidate.line_number or 0, candidate.raw_secret or "")
        if key in seen:
            continue
        seen.add(key)
        raw_candidates.append(candidate)

    return [normalize_finding(candidate) for candidate in raw_candidates]


def _walk_ast(tree: ast.AST, relative_path: str) -> list[RawFinding]:
    candidates: list[RawFinding] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                name = _target_name(target)
                candidate = _candidate_from_value(name, node.value, relative_path)
                if candidate:
                    candidates.append(candidate)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            name = _target_name(node.target)
            candidate = _candidate_from_value(name, node.value, relative_path)
            if candidate:
                candidates.append(candidate)
        elif isinstance(node, ast.Dict):
            candidates.extend(_candidates_from_dict(node, relative_path))

    return candidates


def _candidate_from_value(
    name: str | None,
    value: ast.expr,
    relative_path: str,
) -> RawFinding | None:
    if not name or not _is_credential_name(name):
        return None
    literal = _string_literal(value)
    if literal is None:
        return None  # Not a hard-coded literal (e.g. os.getenv(...)) -> skip.
    return _build_candidate(
        relative_path=relative_path,
        line_number=getattr(value, "lineno", None),
        variable=name,
        literal=literal,
        candidate_type=_candidate_type(name, literal),
    )


def _candidates_from_dict(node: ast.Dict, relative_path: str) -> list[RawFinding]:
    candidates: list[RawFinding] = []
    for key_node, value_node in zip(node.keys, node.values):
        key = _string_literal(key_node) if key_node is not None else None
        if not key or not _is_credential_name(key):
            continue
        literal = _string_literal(value_node)
        if literal is None:
            continue
        candidate = _build_candidate(
            relative_path=relative_path,
            line_number=getattr(value_node, "lineno", None),
            variable=key,
            literal=literal,
            candidate_type=_candidate_type(key, literal),
        )
        if candidate:
            candidates.append(candidate)
    return candidates


def _build_candidate(
    *,
    relative_path: str,
    line_number: int | None,
    variable: str,
    literal: str,
    candidate_type: str,
) -> RawFinding | None:
    stripped = literal.strip()
    if len(stripped) < MIN_VALUE_LENGTH:
        return None
    # A bare Bearer scheme word or an env-var name is not itself a secret.
    if stripped.lower() in CREDENTIAL_KEYWORDS:
        return None

    secret_type = _secret_type(candidate_type)
    return RawFinding(
        detector="python.ast",
        secret_type=secret_type,
        file_path=relative_path,
        line_number=line_number,
        raw_secret=stripped,
        matched_text=f"{variable} = {stripped}",
        confidence=0.6,
        entropy=shannon_entropy(stripped),
        source="python_extractor",
        metadata={"candidate_type": candidate_type, "variable": variable},
    )


def _regex_fallback(source: str, relative_path: str) -> list[RawFinding]:
    """Catch connection strings and Bearer tokens the AST walk does not model."""

    candidates: list[RawFinding] = []
    lines = source.splitlines()

    for line_number, line in enumerate(lines, start=1):
        for match in _CONNECTION_STRING_RE.finditer(line):
            value = match.group(0)
            if not _CONNECTION_WITH_CREDS_RE.search(value):
                continue
            candidates.append(
                RawFinding(
                    detector="python.regex",
                    secret_type="database_url",
                    file_path=relative_path,
                    line_number=line_number,
                    raw_secret=value,
                    matched_text=value,
                    confidence=0.7,
                    entropy=shannon_entropy(value),
                    source="python_extractor",
                    metadata={"candidate_type": "connection_string"},
                )
            )

        bearer = _BEARER_RE.search(line)
        if bearer:
            token = bearer.group(0).split()[-1]
            if len(token) >= MIN_VALUE_LENGTH:
                candidates.append(
                    RawFinding(
                        detector="python.regex",
                        secret_type="bearer_token",
                        file_path=relative_path,
                        line_number=line_number,
                        raw_secret=token,
                        matched_text=bearer.group(0),
                        confidence=0.65,
                        entropy=shannon_entropy(token),
                        source="python_extractor",
                        metadata={"candidate_type": "authorization_header"},
                    )
                )

    return candidates


def _target_name(target: ast.expr) -> str | None:
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    return None


def _string_literal(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_credential_name(name: str) -> bool:
    compact = name.lower().replace("-", "").replace("_", "")
    return any(keyword.replace("_", "") in compact for keyword in CREDENTIAL_KEYWORDS)


def _candidate_type(name: str, literal: str) -> str:
    lowered = name.lower()
    if _CONNECTION_STRING_RE.search(literal):
        return "connection_string"
    if "authorization" in lowered:
        return "authorization_header"
    if "password" in lowered or "passwd" in lowered:
        return "password_assignment"
    if "api" in lowered and "key" in lowered:
        return "api_key_assignment"
    if "token" in lowered:
        return "token_assignment"
    return "secret_assignment"


def _secret_type(candidate_type: str) -> str:
    if candidate_type == "connection_string":
        return "database_url"
    if candidate_type == "authorization_header":
        return "bearer_token"
    return "generic_secret"
