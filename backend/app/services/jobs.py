from __future__ import annotations

from typing import Any

from app.api.schemas import ScanCreateRequest
from app.repositories.factory import build_repository
from app.services.scan_service import ScanService

# Module-level repository reused across jobs in a single worker process so the
# in-memory backend (when used) persists results between enqueued jobs.
_worker_repository = None


def _repository():
    global _worker_repository
    if _worker_repository is None:
        _worker_repository = build_repository()
    return _worker_repository


def run_scan_job(payload: dict[str, Any]) -> dict:
    """Process a scan request. Importable by RQ workers via dotted path."""

    request = ScanCreateRequest(**payload)
    service = ScanService(_repository())
    return service.create_scan(request)
