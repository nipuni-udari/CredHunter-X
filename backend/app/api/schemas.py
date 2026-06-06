from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class FindingInput(BaseModel):
    finding_id: str | None = None
    detector: str
    secret_type: str
    file_path: str
    line_number: int | None = None
    redacted_secret: str | None = None
    secret_hash: str | None = None
    confidence: float = 0.0
    entropy: float | None = None
    commit_sha: str | None = None
    rule_id: str | None = None
    description: str | None = None
    context_before: str | None = None
    context_after: str | None = None
    source: str = "api"
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanConfigInput(BaseModel):
    mode: str = "changed-files"
    fail_on: str = "high"
    include_history: bool = False


class FilterConfigInput(BaseModel):
    ignore_paths: list[str] = Field(default_factory=list)
    allow_placeholders: bool = True


class BackendConfigInput(BaseModel):
    url: str | None = None


class CredHunterConfigInput(BaseModel):
    scan: ScanConfigInput = Field(default_factory=ScanConfigInput)
    filters: FilterConfigInput = Field(default_factory=FilterConfigInput)
    backend: BackendConfigInput = Field(default_factory=BackendConfigInput)


class ScanCreateRequest(BaseModel):
    project_id: str
    repository_id: str
    repository_name: str | None = None
    provider: str = "github"
    branch: str | None = None
    commit_sha: str | None = None
    pull_request_number: int | None = None
    github_run_id: str | None = None
    findings: list[FindingInput] = Field(default_factory=list)
    config: CredHunterConfigInput = Field(default_factory=CredHunterConfigInput)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ClassifyFindingRequest(BaseModel):
    finding: FindingInput
    config: CredHunterConfigInput = Field(default_factory=CredHunterConfigInput)


class FeedbackRequest(BaseModel):
    user: str | None = None
    reason: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class SuppressionRequest(FeedbackRequest):
    scope: str = "finding"


class APIResponse(BaseModel):
    status: str
    data: dict[str, Any] | list[dict[str, Any]] | None = None
