from __future__ import annotations

from app.repositories.factory import build_repository
from app.repositories.repository import Repository
from app.services.job_queue import JobQueue, build_job_queue

_repository: Repository | None = None
_job_queue: JobQueue | None = None


def get_repository() -> Repository:
    global _repository
    if _repository is None:
        _repository = build_repository()
    return _repository


def set_repository(repository: Repository | None) -> None:
    global _repository
    _repository = repository


def get_job_queue() -> JobQueue:
    global _job_queue
    if _job_queue is None:
        _job_queue = build_job_queue()
    return _job_queue


def set_job_queue(queue: JobQueue | None) -> None:
    global _job_queue
    _job_queue = queue
