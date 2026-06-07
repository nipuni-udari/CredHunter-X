from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.api.schemas import ClassifyFindingRequest, FeedbackRequest, SuppressionRequest, ValidateFindingRequest
from app.ci.config import BackendConfig, CredHunterConfig, FilterConfig, LLMConfig, ScanConfig, ValidationConfig
from app.ci.decision import evaluate_findings
from app.repositories.repository import Repository

from .finding_conversion import input_to_normalized_finding
from .llm_filter_service import LLMFilterService
from .schema_utils import model_to_dict
from .validation_service import ValidationService


class FindingService:
    def __init__(self, repository: Repository) -> None:
        self.repository = repository

    def classify_finding(self, request: ClassifyFindingRequest) -> dict:
        finding = input_to_normalized_finding(request.finding)
        config = _config_from_request(request)
        llm_assessments = LLMFilterService(config).classify_findings([finding], config)
        decision = evaluate_findings([finding], config, llm_assessments)
        return decision.findings[0].to_dict()

    def validate_finding(self, request: ValidateFindingRequest) -> dict:
        finding = input_to_normalized_finding(request.finding)
        config = _config_from_request(request)
        return ValidationService(config).validate_finding(finding, request.raw_secret).to_dict()

    def suppress_finding(self, finding_id: str, request: SuppressionRequest) -> dict | None:
        existing = self.repository.get_finding(finding_id)
        if not existing:
            return None

        now = _now()
        updated = self.repository.update_finding(
            finding_id,
            {
                "suppressed": True,
                "action": "ignore",
                "suppression": {
                    "scope": request.scope,
                    "user": request.user,
                    "reason": request.reason,
                    "metadata": request.metadata,
                    "created_at": now,
                },
                "updated_at": now,
            },
        )
        self._audit(existing, "finding_suppressed", request)
        return updated

    def mark_finding(self, finding_id: str, label: str, request: FeedbackRequest) -> dict | None:
        existing = self.repository.get_finding(finding_id)
        if not existing:
            return None

        now = _now()
        updated = self.repository.update_finding(
            finding_id,
            {
                "feedback": {
                    "label": label,
                    "user": request.user,
                    "reason": request.reason,
                    "metadata": request.metadata,
                    "created_at": now,
                },
                "updated_at": now,
            },
        )
        self._audit(existing, f"finding_marked_{label}", request)
        return updated

    def _audit(self, finding: dict, event: str, request: FeedbackRequest) -> None:
        self.repository.create_audit_log(
            {
                "audit_id": f"audit_{uuid.uuid4().hex}",
                "project_id": finding.get("project_id"),
                "repository_id": finding.get("repository_id"),
                "scan_id": finding.get("scan_id"),
                "finding_id": finding.get("finding_id"),
                "event": event,
                "user": request.user,
                "reason": request.reason,
                "created_at": _now(),
            }
        )


def _config_from_request(request: ClassifyFindingRequest) -> CredHunterConfig:
    config = request.config
    return CredHunterConfig(
        scan=ScanConfig(
            mode=config.scan.mode,
            fail_on=config.scan.fail_on,
            include_history=config.scan.include_history,
        ),
        filters=FilterConfig(
            ignore_paths=list(config.filters.ignore_paths),
            allow_placeholders=config.filters.allow_placeholders,
        ),
        backend=BackendConfig(url=config.backend.url),
        llm=LLMConfig(
            enabled=config.llm.enabled,
            provider=config.llm.provider,
            model=config.llm.model,
            min_confidence=config.llm.min_confidence,
        ),
        validation=ValidationConfig(
            enabled=config.validation.enabled,
            network_enabled=config.validation.network_enabled,
            providers=list(config.validation.providers),
            timeout_seconds=config.validation.timeout_seconds,
        ),
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
