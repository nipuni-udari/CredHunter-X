"""On-disk cache for LLM responses.

Every LLM stage (classify, rank, explain, remediate) ultimately issues one
structured JSON call through :func:`app.services.llm_client.openai_json_call`.
Repeated CI runs over the same code re-ask identical questions, so caching that
single call by a stable key makes re-runs free and keeps OpenAI cost down.

The key hashes the prompt version, model, stage instructions, and the full
payload -- which already includes the file, line, candidate type, and masked
context -- so any change to the prompt, model, or finding invalidates the entry.

Safety: payloads are built from redacted/masked data (see ``build_llm_payload``
and ``source_context.mask_line``), never the raw secret, so nothing sensitive is
written to the cache. Cache files live under a gitignored directory.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

# Bump when prompt wording or payload shape changes in a way that should
# invalidate every cached response.
PROMPT_VERSION = "v2"

_DEFAULT_DIR = ".credhunter_cache/llm"


def cache_enabled() -> bool:
    """Caching is on by default; ``CREDHUNTER_LLM_CACHE=false`` turns it off."""

    value = os.getenv("CREDHUNTER_LLM_CACHE")
    if value is None:
        return True
    return value.strip().lower() not in {"0", "false", "no", "off"}


def cache_dir() -> Path:
    return Path(os.getenv("CREDHUNTER_CACHE_DIR", _DEFAULT_DIR))


def make_key(model: str, instructions: str, payload: dict[str, Any]) -> str:
    identity = {
        "prompt_version": PROMPT_VERSION,
        "model": model,
        "instructions": instructions,
        "payload": payload,
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def get(key: str) -> dict[str, Any] | None:
    if not cache_enabled():
        return None
    path = _path_for(key)
    if not path.is_file():
        return None
    try:
        cached = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    result = cached.get("result")
    return result if isinstance(result, dict) else None


def save(key: str, result: dict[str, Any]) -> None:
    if not cache_enabled():
        return
    path = _path_for(key)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"prompt_version": PROMPT_VERSION, "key": key, "result": result}
        path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    except OSError:
        # A cache write failure must never break a scan.
        return


def _path_for(key: str) -> Path:
    # Shard by the first two hex chars to keep directories small.
    return cache_dir() / key[:2] / f"{key}.json"
