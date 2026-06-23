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
from typing import Any

from app.ci.config import CredHunterConfig
from app.core.env import load_local_env


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
) -> dict[str, Any]:
    """Issue one structured-output OpenAI call and parse the JSON response."""

    from openai import OpenAI

    load_local_env()
    model = os.getenv("CREDHUNTER_OPENAI_MODEL", config.llm.model)
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    response = client.responses.create(
        model=model,
        instructions=instructions,
        input=json.dumps(payload, sort_keys=True),
        max_output_tokens=max_output_tokens,
        store=False,
    )
    return json.loads(response.output_text)
