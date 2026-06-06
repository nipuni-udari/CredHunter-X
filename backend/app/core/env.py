from __future__ import annotations

import os
from pathlib import Path


def load_local_env() -> None:
    """Load simple KEY=VALUE pairs from local .env files without overriding env vars."""

    for env_path in _candidate_paths():
        if env_path.exists():
            _load_file(env_path)


def _candidate_paths() -> list[Path]:
    backend_dir = Path(__file__).resolve().parents[2]
    project_dir = backend_dir.parent
    return [project_dir / ".env", backend_dir / ".env"]


def _load_file(path: Path) -> None:
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = _strip_quotes(value.strip())
        if key and key not in os.environ:
            os.environ[key] = value


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value
