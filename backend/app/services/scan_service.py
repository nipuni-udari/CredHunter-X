from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.api.schemas import ScanCreateRequest
from app.ci.config import BackendConfig, CredHunterConfig, FilterConfig, LLMConfig, ScanConfig, ValidationConfig
from app.ci.decision import CIDecision, FindingDecision, evaluate_findings
from app.repositories.repository import Repository
from app.scanner.models import NormalizedFinding
from app.services.false_positive_filter import FalsePositiveAssessment
from app.services.llm_filter_service import LLMClassification
from app.services.risk_scoring_service import RiskComponent, RiskScore
from app.services.validation_service import ValidationResult

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

    def get_scan_decision(self, scan_id: str) -> CIDecision | None:
        scan = self.repository.get_scan(scan_id)
        if not scan:
            return None

        findings = [_decision_from_stored_finding(item) for item in scan.get("findings", [])]
        decision_doc = scan.get("decision", {})
        return CIDecision(
            action=decision_doc.get("action", "pass"),
            exit_code=int(decision_doc.get("exit_code", 0)),
            finding_count=int(decision_doc.get("finding_count", len(findings))),
            blocking_count=int(decision_doc.get("blocking_count", 0)),
            warning_count=int(decision_doc.get("warning_count", 0)),
            manual_review_count=int(decision_doc.get("manual_review_count", 0)),
            ignored_count=int(decision_doc.get("ignored_count", 0)),
            findings=findings,
        )


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


def _decision_from_stored_finding(payload: dict) -> FindingDecision:
    finding_keys = {
        "finding_id",
        "detector",
        "secret_type",
        "file_path",
        "line_number",
        "redacted_secret",
        "secret_hash",
        "confidence",
        "entropy",
        "commit_sha",
        "rule_id",
        "description",
        "context_before",
        "context_after",
        "source",
        "metadata",
    }
    finding_payload = {key: payload.get(key) for key in finding_keys}
    finding_payload["metadata"] = finding_payload.get("metadata") or {}
    finding = NormalizedFinding(**finding_payload)
    return FindingDecision(
        finding=finding,
        risk_level=payload.get("risk_level", "low"),
        action=payload.get("action", "pass"),
        reason=payload.get("decision_reason", ""),
        false_positive_assessment=_false_positive_from_payload(payload.get("false_positive_filter")),
        llm_classification=_llm_from_payload(payload.get("llm_filter")),
        risk_score=_risk_score_from_payload(payload.get("risk_score")),
        validation_result=_validation_from_payload(payload.get("validation")),
    )


def _false_positive_from_payload(payload: dict | None) -> FalsePositiveAssessment | None:
    if not payload:
        return None
    return FalsePositiveAssessment(
        classification=payload.get("classification", "uncertain"),
        ignored=bool(payload.get("ignored", False)),
        risk_override=payload.get("risk_override"),
        reasons=list(payload.get("reasons") or []),
        signals=dict(payload.get("signals") or {}),
    )


def _llm_from_payload(payload: dict | None) -> LLMClassification | None:
    if not payload:
        return None
    return LLMClassification(
        classification=payload.get("classification", "uncertain"),
        confidence=float(payload.get("confidence", 0.0)),
        reason=payload.get("reason", ""),
        recommended_action=payload.get("recommended_action", "keep_rule_decision"),
        model=payload.get("model", ""),
        used=bool(payload.get("used", False)),
        skipped_reason=payload.get("skipped_reason"),
        metadata=dict(payload.get("metadata") or {}),
    )


def _risk_score_from_payload(payload: dict | None) -> RiskScore | None:
    if not payload:
        return None
    return RiskScore(
        score=int(payload.get("score", 0)),
        risk_level=payload.get("risk_level", "low"),
        recommended_action=payload.get("recommended_action", "pass"),
        components=[
            RiskComponent(
                name=item.get("name", ""),
                value=int(item.get("value", 0)),
                reason=item.get("reason", ""),
            )
            for item in payload.get("components", [])
        ],
    )


def _validation_from_payload(payload: dict | None) -> ValidationResult | None:
    if not payload:
        return None
    return ValidationResult(
        provider=payload.get("provider", ""),
        status=payload.get("status", ""),
        active=payload.get("active"),
        reason=payload.get("reason", ""),
        checked=bool(payload.get("checked", False)),
        network_used=bool(payload.get("network_used", False)),
        metadata=dict(payload.get("metadata") or {}),
    )
