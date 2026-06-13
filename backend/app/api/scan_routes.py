from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.api.schemas import ScanCreateRequest
from app.repositories.repository import Repository
from app.reporting.markdown import build_pr_comment
from app.services.job_queue import JobQueue
from app.services.scan_service import ScanService

from .dependencies import get_job_queue, get_repository

router = APIRouter(tags=["scans"])


@router.post("/scans", status_code=201)
def create_scan(
    request: ScanCreateRequest,
    repository: Repository = Depends(get_repository),
) -> dict:
    service = ScanService(repository)
    return service.create_scan(request)


@router.post("/scans/async", status_code=202)
def create_scan_async(
    request: ScanCreateRequest,
    queue: JobQueue = Depends(get_job_queue),
) -> dict:
    job_id = queue.enqueue(request.model_dump(mode="json"))
    record = queue.get(job_id)
    if record:
        return record
    return {"job_id": job_id, "status": "queued", "result": None, "error": None}


@router.get("/jobs/{job_id}")
def get_job_status(job_id: str, queue: JobQueue = Depends(get_job_queue)) -> dict:
    record = queue.get(job_id)
    if not record:
        raise HTTPException(status_code=404, detail="Job not found")
    return record


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str, repository: Repository = Depends(get_repository)) -> dict:
    scan = repository.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/scans/{scan_id}/pr-comment")
def get_scan_pr_comment(scan_id: str, repository: Repository = Depends(get_repository)) -> dict:
    service = ScanService(repository)
    decision = service.get_scan_decision(scan_id)
    if not decision:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"scan_id": scan_id, "markdown": build_pr_comment(decision)}
