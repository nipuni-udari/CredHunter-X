"""Source context enrichment.

After candidates are generated (Gitleaks + the Python extractor), this stage
reads the source file around each finding and attaches the surrounding code so
later stages -- the local false-positive filter and the LLM -- see *where* and
*how* a value is used, not just the value itself.

Two safety rules are absolute here:

- The target line (the line the secret sits on) is **masked** before it is
  stored anywhere. We never persist or forward the raw secret value.
- The surrounding ``context_before`` / ``context_after`` lines are kept as-is so
  the reader can judge intent (assignment vs. ``os.getenv`` vs. a comment), and
  an ``env_reference`` signal is recorded when the target line merely reads a
  value from the environment / a secret manager rather than hard-coding one.
"""

from __future__ import annotations

import re
from pathlib import Path

from .models import NormalizedFinding

DEFAULT_CONTEXT_LINES = 5
MAX_FILE_BYTES = 2_000_000

# Reads of a value from the environment or a secret manager -- these are safe
# patterns, not hard-coded secrets, and must never be sent to the paid LLM.
ENV_REFERENCE_PATTERN = re.compile(
    r"(?i)\b(?:os\.environ(?:\.get)?|os\.getenv|getenv|environ\[|"
    r"process\.env|secretmanager|secrets_manager|get_secret|"
    r"config\(|settings\.|vault\.|ssm\.|parameter_store)\b"
)

# Quoted string literals; their contents are masked on the target line.
_QUOTED_RE = re.compile(r"""(['"])(.*?)\1""")
# Bare high-entropy-ish tokens (long runs of secret-shaped characters).
_LONG_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-./+=]{16,}")


def enrich_with_source_context(
    findings: list[NormalizedFinding],
    repo_path: str | Path,
    *,
    before: int = DEFAULT_CONTEXT_LINES,
    after: int = DEFAULT_CONTEXT_LINES,
) -> list[NormalizedFinding]:
    """Attach masked source context to every finding that has a resolvable file.

    Mutates and returns the same finding objects. Findings whose file cannot be
    located (e.g. a history-only Gitleaks hit) are left untouched -- enrichment
    is best-effort and never fails the scan.
    """

    root = Path(repo_path)
    cache: dict[Path, list[str] | None] = {}

    for finding in findings:
        lines = _read_lines(finding.file_path, root, cache)
        if lines is None or not finding.line_number:
            continue
        _attach_context(finding, lines, before, after)

    return findings


def _attach_context(
    finding: NormalizedFinding,
    lines: list[str],
    before: int,
    after: int,
) -> None:
    index = finding.line_number - 1  # 1-based line numbers -> 0-based list.
    if index < 0 or index >= len(lines):
        return

    start = max(0, index - before)
    end = min(len(lines), index + after + 1)

    target_line = lines[index]
    # Mask every line we keep, not just the target: a neighbouring line may carry
    # its own secret, and context is serialised into reports / prompts / cache.
    context_before = [mask_line(line) for line in lines[start:index]]
    context_after = [mask_line(line) for line in lines[index + 1 : end]]

    finding.context_before = "\n".join(context_before) or None
    finding.context_after = "\n".join(context_after) or None

    signals = finding.metadata.setdefault("signals", {})
    signals["env_reference"] = bool(ENV_REFERENCE_PATTERN.search(target_line))
    # Store only the masked target line -- never the raw secret value.
    finding.metadata["target_line"] = mask_line(target_line)
    finding.metadata["context_enriched"] = True


def mask_line(line: str) -> str:
    """Return ``line`` with any secret-shaped value replaced by ``****``.

    Conservative by design: it over-masks (long quoted literals and bare tokens)
    rather than risk leaking a real secret into a report, log, or cache file.
    Short identifiers such as an env-var name (``"API_KEY"``) are left intact so
    the masked line still reads as recognisable code.
    """

    def mask_quoted(match: re.Match[str]) -> str:
        quote, inner = match.group(1), match.group(2)
        return f"{quote}{_mask_value(inner)}{quote}"

    masked = _QUOTED_RE.sub(mask_quoted, line)
    masked = _LONG_TOKEN_RE.sub(lambda m: _mask_value(m.group(0)), masked)
    return masked.rstrip("\n")


def _mask_value(value: str) -> str:
    if len(value) <= 8:
        return value
    return f"{value[:2]}****{value[-2:]}"


def _read_lines(
    file_path: str,
    root: Path,
    cache: dict[Path, list[str] | None],
) -> list[str] | None:
    resolved = _resolve(file_path, root)
    if resolved is None:
        return None
    if resolved in cache:
        return cache[resolved]

    try:
        if resolved.stat().st_size > MAX_FILE_BYTES:
            cache[resolved] = None
            return None
        text = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        cache[resolved] = None
        return None

    lines = text.splitlines()
    cache[resolved] = lines
    return lines


def _resolve(file_path: str, root: Path) -> Path | None:
    """Locate the source file for a finding, tolerating relative/absolute paths."""

    if not file_path or file_path == "unknown":
        return None

    candidate = Path(file_path)
    if candidate.is_absolute() and candidate.is_file():
        return candidate

    joined = root / file_path
    if joined.is_file():
        return joined

    if candidate.is_file():
        return candidate

    return None
