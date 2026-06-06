from __future__ import annotations

from copy import deepcopy


class InMemoryRepository:
    def __init__(self) -> None:
        self.projects: dict[str, dict] = {}
        self.repositories: dict[str, dict] = {}
        self.scans: dict[str, dict] = {}
        self.findings: dict[str, dict] = {}
        self.audit_logs: list[dict] = []

    def create_project(self, project: dict) -> dict:
        self.projects[project["project_id"]] = deepcopy(project)
        return deepcopy(project)

    def create_repository(self, repository: dict) -> dict:
        self.repositories[repository["repository_id"]] = deepcopy(repository)
        return deepcopy(repository)

    def create_scan(self, scan: dict) -> dict:
        self.scans[scan["scan_id"]] = deepcopy(scan)
        return deepcopy(scan)

    def get_scan(self, scan_id: str) -> dict | None:
        scan = self.scans.get(scan_id)
        return deepcopy(scan) if scan else None

    def create_finding(self, finding: dict) -> dict:
        self.findings[finding["finding_id"]] = deepcopy(finding)
        return deepcopy(finding)

    def get_finding(self, finding_id: str) -> dict | None:
        finding = self.findings.get(finding_id)
        return deepcopy(finding) if finding else None

    def list_findings_by_project(self, project_id: str) -> list[dict]:
        return [deepcopy(item) for item in self.findings.values() if item.get("project_id") == project_id]

    def update_finding(self, finding_id: str, updates: dict) -> dict | None:
        if finding_id not in self.findings:
            return None
        self.findings[finding_id].update(deepcopy(updates))
        return deepcopy(self.findings[finding_id])

    def create_audit_log(self, log: dict) -> dict:
        self.audit_logs.append(deepcopy(log))
        return deepcopy(log)
