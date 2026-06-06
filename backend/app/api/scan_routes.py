from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.api.schemas import ScanCreateRequest
from app.repositories.repository import Repository
from app.services.scan_service import ScanService

from .dependencies import get_repository

router = APIRouter(tags=["scans"])


@router.post("/scans", status_code=201)
def create_scan(
    request: ScanCreateRequest,
    repository: Repository = Depends(get_repository),
) -> dict:
    service = ScanService(repository)
    return service.create_scan(request)


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str, repository: Repository = Depends(get_repository)) -> dict:
    scan = repository.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
