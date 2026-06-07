from __future__ import annotations

from fastapi import APIRouter, Depends

from app.repositories.repository import Repository
from app.reporting.markdown import build_feedback_summary

from .dependencies import get_repository

router = APIRouter(tags=["projects"])


@router.get("/projects/{project_id}/findings")
def list_project_findings(
    project_id: str,
    repository: Repository = Depends(get_repository),
) -> dict:
    findings = repository.list_findings_by_project(project_id)
    return {"project_id": project_id, "finding_count": len(findings), "findings": findings}


@router.get("/projects/{project_id}/feedback-summary")
def get_project_feedback_summary(
    project_id: str,
    repository: Repository = Depends(get_repository),
) -> dict:
    findings = repository.list_findings_by_project(project_id)
    return {"project_id": project_id, **build_feedback_summary(findings)}
