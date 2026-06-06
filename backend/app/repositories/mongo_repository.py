from __future__ import annotations

from pymongo import MongoClient, UpdateOne


class MongoRepository:
    def __init__(self, uri: str, database_name: str) -> None:
        self.client = MongoClient(uri)
        self.db = self.client[database_name]
        self._ensure_indexes()

    def create_project(self, project: dict) -> dict:
        self.db.projects.update_one({"project_id": project["project_id"]}, {"$set": project}, upsert=True)
        return project

    def create_repository(self, repository: dict) -> dict:
        self.db.repositories.update_one(
            {"repository_id": repository["repository_id"]},
            {"$set": repository},
            upsert=True,
        )
        return repository

    def create_scan(self, scan: dict) -> dict:
        self.db.scans.insert_one(scan)
        return scan

    def get_scan(self, scan_id: str) -> dict | None:
        return _clean_id(self.db.scans.find_one({"scan_id": scan_id}))

    def create_finding(self, finding: dict) -> dict:
        self.db.findings.update_one(
            {"finding_id": finding["finding_id"]},
            {"$set": finding},
            upsert=True,
        )
        return finding

    def bulk_create_findings(self, findings: list[dict]) -> None:
        if not findings:
            return
        operations = [
            UpdateOne({"finding_id": finding["finding_id"]}, {"$set": finding}, upsert=True)
            for finding in findings
        ]
        self.db.findings.bulk_write(operations)

    def get_finding(self, finding_id: str) -> dict | None:
        return _clean_id(self.db.findings.find_one({"finding_id": finding_id}))

    def list_findings_by_project(self, project_id: str) -> list[dict]:
        return [_clean_id(item) for item in self.db.findings.find({"project_id": project_id})]

    def update_finding(self, finding_id: str, updates: dict) -> dict | None:
        self.db.findings.update_one({"finding_id": finding_id}, {"$set": updates})
        return self.get_finding(finding_id)

    def create_audit_log(self, log: dict) -> dict:
        self.db.audit_logs.insert_one(log)
        return log

    def _ensure_indexes(self) -> None:
        self.db.projects.create_index("project_id", unique=True)
        self.db.repositories.create_index("repository_id", unique=True)
        self.db.scans.create_index("scan_id", unique=True)
        self.db.scans.create_index([("project_id", 1), ("created_at", -1)])
        self.db.findings.create_index("finding_id", unique=True)
        self.db.findings.create_index("secret_hash")
        self.db.findings.create_index([("project_id", 1), ("risk_level", 1)])
        self.db.findings.create_index([("repository_id", 1), ("created_at", -1)])
        self.db.audit_logs.create_index([("project_id", 1), ("created_at", -1)])


def _clean_id(document: dict | None) -> dict | None:
    if not document:
        return None
    document.pop("_id", None)
    return document
