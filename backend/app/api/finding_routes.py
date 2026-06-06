from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.api.schemas import ClassifyFindingRequest, FeedbackRequest, SuppressionRequest
from app.repositories.repository import Repository
from app.services.finding_service import FindingService

from .dependencies import get_repository

router = APIRouter(tags=["findings"])


@router.post("/findings/classify")
def classify_finding(
    request: ClassifyFindingRequest,
    repository: Repository = Depends(get_repository),
) -> dict:
    service = FindingService(repository)
    return service.classify_finding(request)


@router.post("/findings/{finding_id}/suppress")
def suppress_finding(
    finding_id: str,
    request: SuppressionRequest,
    repository: Repository = Depends(get_repository),
) -> dict:
    service = FindingService(repository)
    result = service.suppress_finding(finding_id, request)
    if not result:
        raise HTTPException(status_code=404, detail="Finding not found")
    return result


@router.post("/findings/{finding_id}/mark-true-positive")
def mark_true_positive(
    finding_id: str,
    request: FeedbackRequest,
    repository: Repository = Depends(get_repository),
) -> dict:
    service = FindingService(repository)
    result = service.mark_finding(finding_id, "true_positive", request)
    if not result:
        raise HTTPException(status_code=404, detail="Finding not found")
    return result


@router.post("/findings/{finding_id}/mark-false-positive")
def mark_false_positive(
    finding_id: str,
    request: FeedbackRequest,
    repository: Repository = Depends(get_repository),
) -> dict:
    service = FindingService(repository)
    result = service.mark_finding(finding_id, "false_positive", request)
    if not result:
        raise HTTPException(status_code=404, detail="Finding not found")
    return result
