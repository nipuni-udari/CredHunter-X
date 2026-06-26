"""Shared OpenAI access used by every LLM pipeline stage.

The classifier, ranker, explainer and remediation stages all talk to OpenAI the
same way: a single JSON-in / JSON-out call with structured output and no server
side storage. Centralising it keeps the per-stage modules focused on prompt and
validation logic, and gives one place to apply the readiness checks (config flag
and API key) every stage shares.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

from app.ci.config import CredHunterConfig
from app.core.env import load_local_env
from app.services import llm_cache


def llm_ready(config: CredHunterConfig) -> str | None:
    """Return a skip reason if the LLM cannot run, otherwise ``None``."""

    load_local_env()
    if not config.llm.enabled:
        return "LLM filtering is disabled in configuration."
    if not os.getenv("OPENAI_API_KEY"):
        return "OPENAI_API_KEY is not set."
    return None


def openai_json_call(
    config: CredHunterConfig,
    instructions: str,
    payload: dict[str, Any],
    max_output_tokens: int,
    schema_name: str | None = None,
    schema: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Issue one structured-output OpenAI call and parse the JSON response.

    Responses are cached on disk keyed by (prompt version, model, instructions,
    payload), so a repeated run over unchanged code reuses the prior result
    instead of paying for another call. The cache is bypassed transparently when
    disabled via ``CREDHUNTER_LLM_CACHE=false``.
    """

    load_local_env()
    model = os.getenv("CREDHUNTER_OPENAI_MODEL", config.llm.model)
    user_prompt = json.dumps(payload, sort_keys=True)

    if schema_name and schema:
        return call_llm_json(model, instructions, user_prompt, schema_name, schema)

    cache_key = llm_cache.make_key(model, instructions, payload)
    cached = llm_cache.get(cache_key)
    if cached is not None:
        return cached

    from openai import OpenAI

    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    response = client.responses.create(
        model=model,
        instructions=instructions,
        input=user_prompt,
        max_output_tokens=max_output_tokens,
        store=False,
    )
    result = parse_json_response(response.output_text)
    llm_cache.save(cache_key, result)
    return result


def call_llm_json(
    model: str,
    system_prompt: str,
    user_prompt: str,
    schema_name: str,
    schema: dict[str, Any],
) -> dict[str, Any]:
    """Call OpenAI with strict Structured Outputs and return the JSON object."""

    load_local_env()
    cache_payload = {
        "user_prompt": user_prompt,
        "schema_name": schema_name,
        "schema": schema,
    }
    cache_key = llm_cache.make_key(model, f"structured:{schema_name}:{system_prompt}", cache_payload)
    cached = llm_cache.get(cache_key)
    if cached is not None:
        return cached

    from openai import OpenAI

    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    response = client.responses.create(
        model=model,
        instructions=system_prompt,
        input=user_prompt,
        text={
            "format": {
                "type": "json_schema",
                "name": schema_name,
                "strict": True,
                "schema": schema,
            }
        },
        store=False,
    )
    result = _response_json(response)
    llm_cache.save(cache_key, result)
    return result


def _response_json(response: Any) -> dict[str, Any]:
    parsed = getattr(response, "output_parsed", None)
    if isinstance(parsed, dict):
        return parsed

    output_text = getattr(response, "output_text", None)
    if isinstance(output_text, str) and output_text.strip():
        return parse_json_response(output_text)

    for item in getattr(response, "output", []) or []:
        for content in getattr(item, "content", []) or []:
            parsed = getattr(content, "parsed", None)
            if isinstance(parsed, dict):
                return parsed
            text = getattr(content, "text", None)
            if isinstance(text, str) and text.strip():
                return parse_json_response(text)

    raise ValueError("LLM response did not contain a valid JSON object.")


def parse_json_response(text: str) -> dict[str, Any]:
    """Parse an LLM response that should contain one JSON object.

    Models are instructed to return JSON only, but in practice they can wrap it
    in Markdown fences or add a short sentence before/after it. Keep parsing
    forgiving here so every LLM stage gets the same repair behavior.
    """

    attempts = [text, _strip_markdown_fence(text)]
    for candidate in attempts:
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

    extracted = _extract_first_json_object(text)
    if extracted is not None:
        try:
            parsed = json.loads(extracted)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

    raise ValueError("LLM response did not contain a valid JSON object.")


def _strip_markdown_fence(text: str) -> str:
    stripped = text.strip()
    match = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", stripped, flags=re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1).strip()
    return stripped


def _extract_first_json_object(text: str) -> str | None:
    start = text.find("{")
    while start != -1:
        depth = 0
        in_string = False
        escaped = False
        for index in range(start, len(text)):
            char = text[index]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return text[start : index + 1]
        start = text.find("{", start + 1)
    return None
