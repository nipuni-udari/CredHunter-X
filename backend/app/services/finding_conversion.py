from __future__ import annotations

import hashlib
import json

from app.api.schemas import FindingInput
from app.scanner.models import NormalizedFinding

from .schema_utils import model_to_dict


def input_to_normalized_finding(finding: FindingInput) -> NormalizedFinding:
    data = model_to_dict(finding)
    if not data.get("finding_id"):
        data["finding_id"] = _build_finding_id(data)
    return NormalizedFinding(**data)


def _build_finding_id(data: dict) -> str:
    identity = {
        "detector": data.get("detector"),
        "secret_type": data.get("secret_type"),
        "file_path": data.get("file_path"),
        "line_number": data.get("line_number"),
        "secret_hash": data.get("secret_hash"),
        "rule_id": data.get("rule_id"),
        "commit_sha": data.get("commit_sha"),
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:24]
