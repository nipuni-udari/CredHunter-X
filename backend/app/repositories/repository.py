from __future__ import annotations

from typing import Protocol


class Repository(Protocol):
    def create_project(self, project: dict) -> dict:
        ...

    def create_repository(self, repository: dict) -> dict:
        ...

    def create_scan(self, scan: dict) -> dict:
        ...

    def get_scan(self, scan_id: str) -> dict | None:
        ...

    def create_finding(self, finding: dict) -> dict:
        ...

    def get_finding(self, finding_id: str) -> dict | None:
        ...

    def list_findings_by_project(self, project_id: str) -> list[dict]:
        ...

    def update_finding(self, finding_id: str, updates: dict) -> dict | None:
        ...

    def create_audit_log(self, log: dict) -> dict:
        ...
