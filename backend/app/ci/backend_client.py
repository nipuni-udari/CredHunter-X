from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from app.ci.config import CredHunterConfig
from app.scanner.models import NormalizedFinding


class BackendSubmissionError(RuntimeError):
    pass


def build_scan_payload(findings: list[NormalizedFinding], config: CredHunterConfig) -> dict[str, Any]:
    repository_name = os.getenv("GITHUB_REPOSITORY", "local/repository")
    repository_id = os.getenv("CREDHUNTER_REPOSITORY_ID", repository_name)
    project_id = os.getenv("CREDHUNTER_PROJECT_ID", repository_name)

    return {
        "project_id": project_id,
        "repository_id": repository_id,
        "repository_name": repository_name,
        "provider": "github" if os.getenv("GITHUB_ACTIONS") else "local",
        "branch": os.getenv("GITHUB_REF_NAME"),
        "commit_sha": os.getenv("GITHUB_SHA"),
        "pull_request_number": _pull_request_number(),
        "github_run_id": os.getenv("GITHUB_RUN_ID"),
        "findings": [finding.to_dict() for finding in findings],
        "config": {
            "scan": {
                "mode": config.scan.mode,
                "fail_on": config.scan.fail_on,
                "include_history": config.scan.include_history,
            },
            "filters": {
                "ignore_paths": config.filters.ignore_paths,
                "allow_placeholders": config.filters.allow_placeholders,
            },
            "backend": {"url": config.backend.url},
        },
        "metadata": {
            "github_workflow": os.getenv("GITHUB_WORKFLOW"),
            "github_event_name": os.getenv("GITHUB_EVENT_NAME"),
            "github_actor": os.getenv("GITHUB_ACTOR"),
        },
    }


def submit_scan_to_backend(base_url: str, findings: list[NormalizedFinding], config: CredHunterConfig) -> dict:
    url = f"{base_url.rstrip('/')}/api/scans"
    payload = json.dumps(build_scan_payload(findings, config)).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            body = response.read().decode("utf-8")
            return json.loads(body)
    except urllib.error.URLError as exc:
        raise BackendSubmissionError(f"Failed to submit scan to backend: {exc}") from exc


def _pull_request_number() -> int | None:
    value = os.getenv("GITHUB_PR_NUMBER") or os.getenv("PR_NUMBER")
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None
