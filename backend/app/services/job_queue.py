from __future__ import annotations

import os
import uuid
from typing import Any, Protocol


class JobQueue(Protocol):
    def enqueue(self, payload: dict[str, Any]) -> str:
        ...

    def get(self, job_id: str) -> dict | None:
        ...


class InlineJobQueue:
    """Executes jobs synchronously in-process.

    Default when no Redis is configured. Runs against the API's shared
    repository so results are immediately retrievable through the API.
    """

    def __init__(self) -> None:
        self._jobs: dict[str, dict] = {}

    def enqueue(self, payload: dict[str, Any]) -> str:
        job_id = f"job_{uuid.uuid4().hex}"
        try:
            result = self._run(payload)
            self._jobs[job_id] = {"job_id": job_id, "status": "finished", "result": result, "error": None}
        except Exception as exc:  # surface job failures via status rather than crashing the request
            self._jobs[job_id] = {"job_id": job_id, "status": "failed", "result": None, "error": str(exc)}
        return job_id

    def get(self, job_id: str) -> dict | None:
        return self._jobs.get(job_id)

    @staticmethod
    def _run(payload: dict[str, Any]) -> dict:
        from app.api.dependencies import get_repository
        from app.api.schemas import ScanCreateRequest
        from app.services.scan_service import ScanService

        request = ScanCreateRequest(**payload)
        return ScanService(get_repository()).create_scan(request)


class RedisJobQueue:
    """Enqueues scan jobs onto an RQ queue backed by Redis."""

    def __init__(self, redis_url: str, queue_name: str = "credhunter") -> None:
        from redis import Redis
        from rq import Queue

        self._connection = Redis.from_url(redis_url)
        self._connection.ping()
        self._queue = Queue(queue_name, connection=self._connection)

    def enqueue(self, payload: dict[str, Any]) -> str:
        job = self._queue.enqueue("app.services.jobs.run_scan_job", payload, job_timeout=600)
        return job.id

    def get(self, job_id: str) -> dict | None:
        from rq.exceptions import NoSuchJobError
        from rq.job import Job

        try:
            job = Job.fetch(job_id, connection=self._connection)
        except NoSuchJobError:
            return None

        error = None
        if job.is_failed and job.exc_info:
            error = job.exc_info.strip().splitlines()[-1]
        return {
            "job_id": job_id,
            "status": job.get_status(refresh=True),
            "result": job.result,
            "error": error,
        }


def build_job_queue() -> JobQueue:
    """Build a Redis-backed queue when CREDHUNTER_REDIS_URL is set, else inline."""

    redis_url = os.getenv("CREDHUNTER_REDIS_URL")
    if redis_url:
        try:
            return RedisJobQueue(redis_url, os.getenv("CREDHUNTER_QUEUE_NAME", "credhunter"))
        except Exception:  # Redis unreachable or rq missing: degrade to inline processing
            pass
    return InlineJobQueue()
