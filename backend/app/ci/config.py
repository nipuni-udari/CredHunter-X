from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.env import load_local_env


@dataclass(slots=True)
class ScanConfig:
    mode: str = "changed-files"
    fail_on: str = "high"
    include_history: bool = False


@dataclass(slots=True)
class FilterConfig:
    ignore_paths: list[str] = field(default_factory=list)
    allow_placeholders: bool = True
    # Generic-secret heuristics. Real provider tokens (github/aws/jwt/...) and
    # private keys are never downgraded by these; they only apply to
    # generic_secret / generic_high_entropy_secret findings.
    min_entropy: float = 1.8
    min_secret_length: int = 4
    require_secret_value: bool = True


@dataclass(slots=True)
class BackendConfig:
    url: str | None = None


@dataclass(slots=True)
class LLMConfig:
    enabled: bool = False
    provider: str = "openai"
    model: str = "o4-mini"
    min_confidence: float = 0.8
    # "single"  -> one prompt returns classification + justification together.
    # "agentic" -> multi-step: classify, then justify/verify (RQ2 ablation).
    workflow: str = "single"


@dataclass(slots=True)
class ValidationConfig:
    enabled: bool = False
    network_enabled: bool = False
    providers: list[str] = field(default_factory=lambda: ["github", "jwt", "database_url"])
    timeout_seconds: float = 5.0


@dataclass(slots=True)
class CredHunterConfig:
    scan: ScanConfig = field(default_factory=ScanConfig)
    filters: FilterConfig = field(default_factory=FilterConfig)
    backend: BackendConfig = field(default_factory=BackendConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    validation: ValidationConfig = field(default_factory=ValidationConfig)


def load_config(path: str | Path | None) -> CredHunterConfig:
    load_local_env()
    if not path:
        return _with_env_overrides(CredHunterConfig())

    config_path = Path(path)
    if not config_path.exists():
        return _with_env_overrides(CredHunterConfig())

    text = config_path.read_text(encoding="utf-8")
    if config_path.suffix.lower() == ".json":
        data = json.loads(text)
    else:
        data = _parse_minimal_yaml(text)

    return _with_env_overrides(_from_dict(data))


def _from_dict(data: dict[str, Any]) -> CredHunterConfig:
    scan = data.get("scan") or {}
    filters = data.get("filters") or {}
    backend = data.get("backend") or {}
    llm = data.get("llm") or {}
    validation = data.get("validation") or {}

    return CredHunterConfig(
        scan=ScanConfig(
            mode=str(scan.get("mode", "changed-files")),
            fail_on=str(scan.get("fail_on", "high")).lower(),
            include_history=_to_bool(scan.get("include_history", False)),
        ),
        filters=FilterConfig(
            ignore_paths=[str(item) for item in filters.get("ignore_paths", [])],
            allow_placeholders=_to_bool(filters.get("allow_placeholders", True)),
            min_entropy=_to_float(filters.get("min_entropy", 1.8), 1.8),
            min_secret_length=int(_to_float(filters.get("min_secret_length", 4), 4)),
            require_secret_value=_to_bool(filters.get("require_secret_value", True)),
        ),
        backend=BackendConfig(url=_optional_string(backend.get("url"))),
        llm=LLMConfig(
            enabled=_to_bool(llm.get("enabled", False)),
            provider=str(llm.get("provider", "openai")),
            model=str(llm.get("model", "o4-mini")),
            min_confidence=_to_float(llm.get("min_confidence", 0.8), 0.8),
            workflow=str(llm.get("workflow", "single")).lower(),
        ),
        validation=ValidationConfig(
            enabled=_to_bool(validation.get("enabled", False)),
            network_enabled=_to_bool(validation.get("network_enabled", False)),
            providers=[str(item) for item in validation.get("providers", ["github", "jwt", "database_url"])],
            timeout_seconds=_to_float(validation.get("timeout_seconds", 5.0), 5.0),
        ),
    )


def _parse_minimal_yaml(text: str) -> dict[str, Any]:
    """Parse the small config shape used by CredHunter-X without external deps."""

    data: dict[str, Any] = {}
    current_section: str | None = None
    current_list_key: str | None = None

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue

        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()

        if indent == 0 and stripped.endswith(":"):
            current_section = stripped[:-1]
            data.setdefault(current_section, {})
            current_list_key = None
            continue

        if current_section is None:
            continue

        section = data.setdefault(current_section, {})

        if stripped.startswith("- ") and current_list_key:
            section.setdefault(current_list_key, []).append(_strip_quotes(stripped[2:].strip()))
            continue

        if ":" not in stripped:
            continue

        key, value = stripped.split(":", 1)
        key = key.strip()
        value = value.strip()

        if value == "":
            section[key] = []
            current_list_key = key
        else:
            section[key] = _parse_scalar(value)
            current_list_key = None

    return data


def _parse_scalar(value: str) -> Any:
    cleaned = _strip_quotes(value)
    lowered = cleaned.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    return cleaned


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _optional_string(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    return cleaned or None


def _to_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _with_env_overrides(config: CredHunterConfig) -> CredHunterConfig:
    if os.getenv("CREDHUNTER_OPENAI_MODEL"):
        config.llm.model = os.environ["CREDHUNTER_OPENAI_MODEL"]
    if os.getenv("CREDHUNTER_LLM_ENABLED"):
        config.llm.enabled = _to_bool(os.environ["CREDHUNTER_LLM_ENABLED"])
    if os.getenv("CREDHUNTER_LLM_WORKFLOW"):
        config.llm.workflow = os.environ["CREDHUNTER_LLM_WORKFLOW"].lower()
    if os.getenv("CREDHUNTER_VALIDATION_ENABLED"):
        config.validation.enabled = _to_bool(os.environ["CREDHUNTER_VALIDATION_ENABLED"])
    if os.getenv("CREDHUNTER_VALIDATION_NETWORK_ENABLED"):
        config.validation.network_enabled = _to_bool(os.environ["CREDHUNTER_VALIDATION_NETWORK_ENABLED"])
    return config
