from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.api.schemas import ScanCreateRequest
from app.ci.config import BackendConfig, CredHunterConfig, FilterConfig, LLMConfig, ScanConfig, ValidationConfig
from app.ci.decision import evaluate_findings
from app.repositories.repository import Repository

from .finding_conversion import input_to_normalized_finding
from .llm_filter_service import LLMFilterService
from .schema_utils import model_to_dict


class ScanService:
    def __init__(self, repository: Repository) -> None:
        self.repository = repository

    def create_scan(self, request: ScanCreateRequest) -> dict:
        now = _now()
        scan_id = f"scan_{uuid.uuid4().hex}"

        project = {
            "project_id": request.project_id,
            "provider": request.provider,
            "updated_at": now,
        }
        repository_doc = {
            "repository_id": request.repository_id,
            "project_id": request.project_id,
            "repository_name": request.repository_name,
            "provider": request.provider,
            "updated_at": now,
        }

        findings = [input_to_normalized_finding(item) for item in request.findings]
        config = _config_from_request(request)
        llm_assessments = LLMFilterService(config).classify_findings(findings, config)
        decision = evaluate_findings(findings, config, llm_assessments)

        self.repository.create_project(project)
        self.repository.create_repository(repository_doc)

        finding_docs = []
        for item in decision.findings:
            finding_doc = item.to_dict()
            finding_doc.update(
                {
                    "scan_id": scan_id,
                    "project_id": request.project_id,
                    "repository_id": request.repository_id,
                    "created_at": now,
                    "feedback": None,
                    "suppressed": item.action == "ignore",
                }
            )
            self.repository.create_finding(finding_doc)
            finding_docs.append(finding_doc)

        scan = {
            "scan_id": scan_id,
            "project_id": request.project_id,
            "repository_id": request.repository_id,
            "repository_name": request.repository_name,
            "provider": request.provider,
            "branch": request.branch,
            "commit_sha": request.commit_sha,
            "pull_request_number": request.pull_request_number,
            "github_run_id": request.github_run_id,
            "created_at": now,
            "metadata": request.metadata,
            "decision": {
                "action": decision.action,
                "exit_code": decision.exit_code,
                "finding_count": decision.finding_count,
                "blocking_count": decision.blocking_count,
                "manual_review_count": decision.manual_review_count,
                "warning_count": decision.warning_count,
                "ignored_count": decision.ignored_count,
            },
            "findings": finding_docs,
            "config": model_to_dict(request.config),
        }
        self.repository.create_scan(scan)
        self.repository.create_audit_log(
            {
                "audit_id": f"audit_{uuid.uuid4().hex}",
                "project_id": request.project_id,
                "repository_id": request.repository_id,
                "scan_id": scan_id,
                "event": "scan_created",
                "created_at": now,
            }
        )
        return scan


def _config_from_request(request: ScanCreateRequest) -> CredHunterConfig:
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
