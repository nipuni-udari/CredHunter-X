# Phase 12 Deployment Process

## Purpose

Phase 12 packages CredHunter-X for local, CI, and production deployment.

It adds a Docker image for the FastAPI backend, a local Docker Compose stack, and a GitHub Actions workflow that tests and builds the backend image before publishing it to GHCR on non-pull-request events.

## Local Docker Compose

Run from the repository root:

```bash
docker compose up --build
```

The local stack includes:

- FastAPI backend on `http://localhost:8000`.
- MongoDB for persistent scan, finding, feedback, and audit-log storage.
- Redis for future background jobs.
- Worker process reserved for asynchronous jobs.

Useful checks:

```bash
curl http://localhost:8000/health
curl http://localhost:8000/health/ready
```

The readiness endpoint reports whether the API is configured for MongoDB or in-memory storage.

## Backend Image

The backend image is built from:

```text
backend/Dockerfile
```

The image runs:

```text
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

The image excludes local datasets, tests, docs, virtual environments, and secret-bearing `.env` files through:

```text
backend/.dockerignore
```

## CI Image Build

The Docker image workflow lives at:

```text
.github/workflows/docker-image.yml
```

The workflow:

- Installs backend dependencies.
- Runs the backend unit test suite.
- Builds the backend Docker image.
- Publishes to GitHub Container Registry on `main`, version tags, and manual dispatch.
- Builds without publishing on pull requests.

## Runtime Configuration

Production deployments should provide these values through the platform secret manager:

```text
CREDHUNTER_MONGODB_URI
CREDHUNTER_MONGODB_DATABASE
CREDHUNTER_REDIS_URL
OPENAI_API_KEY
CREDHUNTER_OPENAI_MODEL
CREDHUNTER_LLM_ENABLED
CREDHUNTER_VALIDATION_ENABLED
CREDHUNTER_VALIDATION_NETWORK_ENABLED
```

Do not bake real secrets into the image, Compose file, or GitHub workflow.

## Production Deployment Notes

Recommended production shape:

- Backend container behind HTTPS.
- Managed MongoDB-compatible database.
- Managed Redis-compatible queue.
- Platform secret manager for credentials.
- Role-based access control at the API gateway or application edge.
- Audit logs retained from the `audit_logs` collection.
- Cloud-native metrics/logging or Prometheus/Grafana.

Suggested release flow:

```text
Developer PR
  -> backend tests
  -> Docker image build
  -> scanner check against fixtures
  -> image publish
  -> staging deploy
  -> smoke tests against /health and /health/ready
  -> production deploy
```
