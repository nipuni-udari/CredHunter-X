from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class ScanConfig:
    mode: str = "changed-files"
    fail_on: str = "high"
    include_history: bool = False


@dataclass(slots=True)
class FilterConfig:
    ignore_paths: list[str] = field(default_factory=list)
    allow_placeholders: bool = True


@dataclass(slots=True)
class BackendConfig:
    url: str | None = None


@dataclass(slots=True)
class CredHunterConfig:
    scan: ScanConfig = field(default_factory=ScanConfig)
    filters: FilterConfig = field(default_factory=FilterConfig)
    backend: BackendConfig = field(default_factory=BackendConfig)


def load_config(path: str | Path | None) -> CredHunterConfig:
    if not path:
        return CredHunterConfig()

    config_path = Path(path)
    if not config_path.exists():
        return CredHunterConfig()

    text = config_path.read_text(encoding="utf-8")
    if config_path.suffix.lower() == ".json":
        data = json.loads(text)
    else:
        data = _parse_minimal_yaml(text)

    return _from_dict(data)


def _from_dict(data: dict[str, Any]) -> CredHunterConfig:
    scan = data.get("scan") or {}
    filters = data.get("filters") or {}
    backend = data.get("backend") or {}

    return CredHunterConfig(
        scan=ScanConfig(
            mode=str(scan.get("mode", "changed-files")),
            fail_on=str(scan.get("fail_on", "high")).lower(),
            include_history=_to_bool(scan.get("include_history", False)),
        ),
        filters=FilterConfig(
            ignore_paths=[str(item) for item in filters.get("ignore_paths", [])],
            allow_placeholders=_to_bool(filters.get("allow_placeholders", True)),
        ),
        backend=BackendConfig(url=backend.get("url")),
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
