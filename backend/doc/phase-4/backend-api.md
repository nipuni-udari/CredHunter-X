# Phase 4 Backend API Implementation

## Purpose

Phase 4 adds the FastAPI backend that receives scan results, stores normalized findings, returns CI decisions, and supports finding feedback workflows.

## Implemented Components

API app:

- `backend/app/main.py`
- `backend/app/api/app.py`

Routes:

- `backend/app/api/scan_routes.py`
- `backend/app/api/finding_routes.py`
- `backend/app/api/project_routes.py`

Services:

- `backend/app/services/scan_service.py`
- `backend/app/services/finding_service.py`

Persistence:

- `backend/app/repositories/memory_repository.py`
- `backend/app/repositories/mongo_repository.py`
- `backend/app/repositories/repository.py`

Schemas:

- `backend/app/api/schemas.py`

## API Endpoints

```text
GET  /health
POST /api/scans
GET  /api/scans/{scan_id}
POST /api/findings/classify
GET  /api/projects/{project_id}/findings
POST /api/findings/{finding_id}/suppress
POST /api/findings/{finding_id}/mark-true-positive
POST /api/findings/{finding_id}/mark-false-positive
```

## Storage Mode

The backend supports two storage modes:

```text
Default development/test mode:
  InMemoryRepository

MongoDB mode:
  MongoRepository
```

MongoDB is enabled by setting:

```text
CREDHUNTER_MONGODB_URI
CREDHUNTER_MONGODB_DATABASE
```

If `CREDHUNTER_MONGODB_URI` is not set, the API uses in-memory storage.

## MongoDB Collections

The MongoDB repository uses these collections:

- `projects`
- `repositories`
- `scans`
- `findings`
- `audit_logs`

Future phases can add:

- `classification_results`
- `suppression_rules`
- `user_feedback`

## API Workflow

```text
GitHub Actions
  -> Gitleaks report
  -> CredHunter-X normalization
  -> POST /api/scans
  -> Backend stores scan and findings
  -> Backend evaluates CI decision
  -> Backend returns pass, warn, or fail result
```

The Phase 3 CI command now supports optional backend submission. If `backend.url` is set in `.credhunter.yml`, GitHub Actions posts normalized findings to this API after parsing the Gitleaks report.

## Risk Scoring

Phase 8 adds weighted risk scoring to scan and classification responses. Finding responses include:

```text
risk_score.score
risk_score.risk_level
risk_score.recommended_action
risk_score.components
```

Scan decisions also include:

```text
manual_review_count
```

## Example Scan Request

```json
{
  "project_id": "project-demo",
  "repository_id": "repo-demo",
  "repository_name": "demo/repo",
  "provider": "github",
  "branch": "main",
  "commit_sha": "abc123",
  "pull_request_number": 10,
  "github_run_id": "1001",
  "findings": [
    {
      "detector": "gitleaks",
      "secret_type": "github_token",
      "file_path": "src/config.py",
      "line_number": 7,
      "redacted_secret": "ghp_****7890",
      "secret_hash": "hmac-sha256:example",
      "confidence": 0.85,
      "rule_id": "github-pat",
      "source": "gitleaks_json"
    }
  ],
  "config": {
    "scan": {
      "mode": "changed-files",
      "fail_on": "high",
      "include_history": false
    },
    "filters": {
      "ignore_paths": [],
      "allow_placeholders": true
    },
    "backend": {
      "url": null
    }
  }
}
```

## Run Locally

```bash
uvicorn app.main:app --reload
```

Then open:

```text
http://127.0.0.1:8000/docs
```

## Security Notes

- The API expects normalized findings.
- Raw secrets should not be submitted to the backend.
- Raw secrets are not required for scan storage, classification, or CI decisions.
- Feedback and suppression events are stored as audit logs.
