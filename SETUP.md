# CredHunter-X Setup Guide

This guide explains how to set up CredHunter-X from the beginning after cloning the project.

CredHunter-X is a Git leak detection and false-positive filtering system. The current implementation focuses on the backend, GitHub Actions integration, Gitleaks report processing, rule-based filtering, a four-stage LLM pipeline (classification, ranking, explanation, remediation) that is on by default and falls back to the deterministic engine when no API key is present, optional validation, risk scoring, CredData testing/evaluation, and reporting.

## 1. Prerequisites

Install these before starting:

- Git
- Python 3.10 or newer
- pip
- Gitleaks, optional but recommended
- MongoDB, optional for persistent backend storage

Check Python:

```powershell
python --version
```

Check Git:

```powershell
git --version
```

Check Gitleaks:

```powershell
gitleaks version
```

If Gitleaks is not installed, the backend tests can still run, but real GitHub Actions scanning depends on Gitleaks.

### Install Gitleaks

Gitleaks is the primary secret scanner used by CredHunter-X. CredHunter-X reads the Gitleaks JSON output, normalizes the findings, filters likely false positives, scores risk, and generates reports.

#### Recommended Windows Installation

Use `winget` from PowerShell:

```powershell
winget install --id Gitleaks.Gitleaks -e
```

Close and reopen PowerShell, then verify:

```powershell
gitleaks version
```

If the command is not recognized after installation, restart the terminal or check that the Gitleaks install location was added to your `PATH`.

#### Manual Windows Installation

Use this method if `winget` is not available.

1. Open the official Gitleaks releases page:

   ```text
   https://github.com/gitleaks/gitleaks/releases
   ```

2. Download the Windows 64-bit ZIP file for the latest release. The filename usually looks similar to:

   ```text
   gitleaks_<version>_windows_x64.zip
   ```

3. Extract the ZIP file.

4. Move `gitleaks.exe` to a permanent folder, for example:

   ```text
   C:\Tools\gitleaks\
   ```

5. Add that folder to your Windows `PATH`:

   ```powershell
   [Environment]::SetEnvironmentVariable(
     "Path",
     $env:Path + ";C:\Tools\gitleaks",
     [EnvironmentVariableTarget]::User
   )
   ```

6. Close and reopen PowerShell, then verify:

   ```powershell
   gitleaks version
   ```

#### Alternative Windows Package Managers

If you already use Chocolatey:

```powershell
choco install gitleaks -y
```

If you already use Scoop:

```powershell
scoop install gitleaks
```

#### macOS

Use Homebrew:

```bash
brew install gitleaks
gitleaks version
```

#### Linux

The simplest Linux approach is to download the latest Linux archive from the official releases page, extract it, and place the binary somewhere in your `PATH`, such as `/usr/local/bin`.

Example:

```bash
tar -xzf gitleaks_<version>_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/gitleaks
gitleaks version
```

#### Docker Option

If Docker is installed, you can run Gitleaks without installing the binary directly:

```powershell
docker pull ghcr.io/gitleaks/gitleaks:latest
docker run --rm -v ${PWD}:/repo ghcr.io/gitleaks/gitleaks:latest dir /repo
```

#### Test Gitleaks In This Project

From the project root:

```powershell
gitleaks dir . --no-banner --report-format json --report-path backend\reports\gitleaks-local.json
```

If secrets are found, Gitleaks may return a non-zero exit code. That is expected behavior. Review the generated report carefully and do not commit reports that contain real secret values.

## 2. Clone The Project

```powershell
git clone <repository-url>
cd CredHunter-X
```

Project structure:

```text
CredHunter-X/
  backend/
    app/
    Dataset/
    doc/
    tests/
    .credhunter.yml
    .env.example
    requirements.txt
  .github/
  SETUP.md
```

## 3. Create A Python Virtual Environment

From the project root:

```powershell
cd backend
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

On Linux/macOS:

```bash
source .venv/bin/activate
```

## 4. Install Backend Dependencies

From `backend/`:

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Required packages include:

```text
fastapi
httpx
openai
pydantic
pymongo
uvicorn
```

## 5. Configure Environment Variables

Copy the example env file:

```powershell
Copy-Item .env.example .env
```

On Linux/macOS:

```bash
cp .env.example .env
```

Open `backend/.env` and configure values if needed:

```text
OPENAI_API_KEY=
CREDHUNTER_OPENAI_MODEL=o4-mini
# The LLM pipeline is ON by default. It only calls OpenAI when OPENAI_API_KEY is
# set; without a key every LLM stage is skipped and the deterministic engine runs.
# Set CREDHUNTER_LLM_ENABLED=false to force deterministic-only even with a key.
CREDHUNTER_VALIDATION_ENABLED=false
CREDHUNTER_VALIDATION_NETWORK_ENABLED=false
CREDHUNTER_API_KEYS=
CREDHUNTER_REDIS_URL=redis://localhost:6379/0
CREDHUNTER_QUEUE_NAME=credhunter
```

- `CREDHUNTER_API_KEYS` is a comma-separated list of accepted API keys. When empty, API authentication is disabled (safe for local development). See section 21.
- `CREDHUNTER_REDIS_URL` enables background scan processing via the worker. When unset or unreachable, scans are processed inline. See section 22.
- The LLM pipeline stages can be toggled individually with `CREDHUNTER_LLM_RANK`, `CREDHUNTER_LLM_EXPLAIN`, and `CREDHUNTER_LLM_REMEDIATE` (all default `true`).

Important:

- Do not commit `backend/.env`.
- Do not paste real API keys into source files.
- Leaving `OPENAI_API_KEY` empty is safe: the LLM stages no-op and make no network calls. Add a key only when you want LLM output.
- Keep `CREDHUNTER_VALIDATION_NETWORK_ENABLED=false` unless you intentionally want provider validation network calls.

## 6. Review CredHunter Configuration

Main runtime config:

```text
backend/.credhunter.yml
```

Current default:

```yaml
scan:
  mode: changed-files
  fail_on: high
  include_history: false

filters:
  ignore_paths:
    - docs/**
    - tests/fixtures/**
  allow_placeholders: true

backend:
  url:

llm:
  enabled: true
  provider: openai
  model: o4-mini
  min_confidence: 0.8
  workflow: single
  rank: true
  explain: true
  remediate: true

validation:
  enabled: false
  network_enabled: false
  providers:
    - github
    - jwt
    - database_url
  timeout_seconds: 5
```

For local development, the defaults are safe: the LLM pipeline is on but no-ops
without `OPENAI_API_KEY`, so no network calls are made until you add a key.

## 7. Verify The Dataset

CredData should be located at:

```text
backend/Dataset
```

Important processed files:

```text
backend/Dataset/processed/creddata_python_eval.jsonl
backend/Dataset/processed/creddata_python_eval.summary.json
```

Check the summary:

```powershell
Get-Content .\dataset\processed\creddata_python_eval.summary.json
```

Expected values:

```text
records: 4387
true_secret: 654
false_positive: 3733
```

## 8. Run The Test Suite

From `backend/`:

```powershell
python -m unittest discover -s tests
```

Expected result:

```text
OK
```

The tests cover:

- Scanner normalization
- Gitleaks report parsing
- CI decision logic
- FastAPI endpoints
- Rule-based false-positive filtering
- LLM filtering safety
- Optional validation
- Risk scoring
- CredData testing
- Evaluation metrics
- Reporting and feedback

## 9. Run The Backend API

From `backend/`:

```powershell
uvicorn app.main:app --reload
```

Open:

```text
http://127.0.0.1:8000/docs
```

Health check:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

Expected:

```json
{
  "status": "ok"
}
```

## 10. Run Scanner Utilities

Normalize a Gitleaks report:

```powershell
python -m app.scanner.cli normalize-gitleaks --input tests/fixtures/gitleaks-report.json
```

Run the fallback local scanner:

```powershell
python -m app.scanner.cli scan-path --path tests
```

The fallback scanner is for development only. In the pipeline, Gitleaks is the primary scanner.

## 11. Run CI Decision Locally

From `backend/`:

```powershell
python -m app.ci.cli `
  --gitleaks-report tests/fixtures/gitleaks-report.json `
  --config .credhunter.yml `
  --fail-on critical `
  --json-output tests/fixtures/generated/local-report.json `
  --sarif-output tests/fixtures/generated/local-report.sarif `
  --summary-output tests/fixtures/generated/local-summary.md `
  --pr-comment-output tests/fixtures/generated/local-pr-comment.md
```

Generated files:

```text
local-report.json
local-report.sarif
local-summary.md
local-pr-comment.md
```

## 12. Run CredData Phase 9 Check

Balanced sample:

```powershell
python -m app.evaluation.phase9_runner --balanced --limit 10
```

Write output:

```powershell
python -m app.evaluation.phase9_runner --balanced --limit 20 --output tests/fixtures/generated/phase9-check.json
```

This proves the system can safely load and process CredData records.

## 13. Run CredData Phase 10 Evaluation

Balanced evaluation:

```powershell
python -m app.evaluation.phase10_runner --balanced --limit 20
```

Full CredData Python evaluation:

```powershell
python -m app.evaluation.phase10_runner --output tests/fixtures/generated/phase10-full-evaluation.json
```

Optional Gitleaks baseline report:

```powershell
python -m app.evaluation.phase10_runner --gitleaks-report gitleaks-report.json
```

Metrics include:

- Precision
- Recall
- F1 score
- Accuracy
- False positive rate
- False negative rate
- False-positive reduction
- Manual review reduction

## 14. MongoDB Setup, Optional

By default, the API uses in-memory storage.

To use MongoDB, set:

```powershell
$env:CREDHUNTER_MONGODB_URI="mongodb://localhost:27017"
$env:CREDHUNTER_MONGODB_DATABASE="credhunter_x"
```

Then start the API:

```powershell
uvicorn app.main:app --reload
```

MongoDB collections used:

```text
projects
repositories
scans
findings
audit_logs
```

## 15. LLM Pipeline

The LLM pipeline has four stages that run in order on every Gitleaks candidate:

```text
LLM classify  ->  LLM rank  ->  LLM explain  ->  LLM remediate
```

- **Classify** (`llm_filter_service.py`) — labels each candidate real / false
  positive with a confidence and reason.
- **Rank** (`llm_ranker_service.py`) — refines the deterministic 0–100 risk
  score to prioritise findings.
- **Explain** (`llm_explainer_service.py`) — writes a developer-facing rationale
  for the PR comment.
- **Remediate** (`llm_remediation_service.py`) — proposes fix steps tailored to
  the secret type and file location.

All stages are **on by default**. They call OpenAI only when `OPENAI_API_KEY` is
set; without a key (or on any API error) each stage is skipped and the
deterministic rule filter / risk score / per-type remediation template is used,
so a full result is always produced.

To activate the pipeline, add a key to `backend/.env`:

```text
OPENAI_API_KEY=<your-key>
CREDHUNTER_OPENAI_MODEL=o4-mini
```

`.credhunter.yml` controls the stages (all default `true`):

```yaml
llm:
  enabled: true
  provider: openai
  model: o4-mini
  min_confidence: 0.8
  workflow: single   # single | agentic (classifier ablation)
  rank: true
  explain: true
  remediate: true
```

Toggle individual stages from the CLI with `--llm-rank`, `--llm-explain`,
`--llm-remediate` (or disable them via `rank: false` etc.), and force the whole
pipeline off with `CREDHUNTER_LLM_ENABLED=false`.

Safety behavior:

- Raw secrets are never sent to the LLM; only redacted values and safe metadata.
- Private keys are never downgraded by the classifier and never ranked below
  critical.
- If no API key is configured, or any stage errors, the system falls back to the
  deterministic engine for that stage.

## 16. Secret Validation, Optional

Validation is disabled by default.

To enable local-only validation:

```text
CREDHUNTER_VALIDATION_ENABLED=true
CREDHUNTER_VALIDATION_NETWORK_ENABLED=false
```

To enable provider network validation:

```text
CREDHUNTER_VALIDATION_ENABLED=true
CREDHUNTER_VALIDATION_NETWORK_ENABLED=true
```

Use network validation carefully. It may send tokens to provider APIs for read-only validation.

Supported validators:

- GitHub token validation, network opt-in
- JWT expiration check, local only
- Database URL local/external classification, local only

## 17. GitHub Actions Setup

GitHub Action files:

```text
.github/actions/credhunter-x/action.yml
.github/workflows/credhunter-x.yml
```

The workflow:

```text
checkout repository
setup Python
run Gitleaks
run CredHunter-X
upload JSON/SARIF/PR-comment reports
```

Gitleaks uses `continue-on-error: true` so CredHunter-X can make the final decision after filtering and scoring.

## 18. Deployment With Docker

Deployment files:

```text
backend/Dockerfile
docker-compose.yml
.github/workflows/docker-image.yml
backend/doc/phase-12/deployment-process.md
```

Run the local deployment stack from the project root:

```powershell
docker compose up --build
```

Check the backend:

```powershell
curl http://localhost:8000/health
curl http://localhost:8000/health/ready
```

The Docker image workflow runs backend tests, builds the backend image, and publishes to GHCR on non-pull-request events.

## 21. API Authentication

API endpoints under `/api` support optional API-key authentication. Health endpoints
(`/health`, `/health/ready`) are always open.

- When `CREDHUNTER_API_KEYS` is empty, authentication is disabled. This keeps local
  development and the test suite simple.
- When set to one or more comma-separated keys, every `/api` request must include a
  matching `X-API-Key` header, or it is rejected with `401`.

Enable it:

```powershell
$env:CREDHUNTER_API_KEYS="key-one,key-two"
uvicorn app.main:app --reload
```

Example authenticated request:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/projects/project-demo/findings `
  -Headers @{ "X-API-Key" = "key-one" }
```

## 22. Asynchronous Scans And Background Worker

Scans can be processed synchronously (default) or queued for a background worker.

- `POST /api/scans` processes synchronously and returns the full decision.
- `POST /api/scans/async` enqueues the scan and returns a `job_id`.
- `GET /api/jobs/{job_id}` returns the job status and result.

The queue backend is selected automatically:

- If `CREDHUNTER_REDIS_URL` is set and reachable, jobs run on a Redis/RQ queue.
- Otherwise jobs run inline in-process (so the API still works without Redis).

Start a worker (requires Redis):

```powershell
python -m app.worker
```

With Docker Compose, the `worker`, `redis`, and `mongodb` services are already wired:

```powershell
docker compose up --build
```

## 19. Common Commands

Run all tests:

```powershell
python -m unittest discover -s tests
```

Start API:

```powershell
uvicorn app.main:app --reload
```

Run Phase 9:

```powershell
python -m app.evaluation.phase9_runner --balanced --limit 10
```

Run Phase 10:

```powershell
python -m app.evaluation.phase10_runner --balanced --limit 20
```

Run CI locally:

```powershell
python -m app.ci.cli --gitleaks-report tests/fixtures/gitleaks-report.json --config .credhunter.yml
```

## 20. Troubleshooting

If imports fail, make sure you are in `backend/`:

```powershell
cd backend
```

If dependencies are missing:

```powershell
pip install -r requirements.txt
```

If PowerShell blocks virtual environment activation:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

If the API starts but MongoDB is not used:

```text
CREDHUNTER_MONGODB_URI
```

must be set before starting `uvicorn`.

If the LLM stages are skipped (output falls back to deterministic), the key is
missing. Set:

```text
OPENAI_API_KEY=<your-key>
```

The pipeline is enabled by default, so the key is all that is required. Make sure
`CREDHUNTER_LLM_ENABLED` is not set to `false` in your environment or `.env`.

## 20. Security Rules

Do not commit:

- `backend/.env`
- API keys
- Raw secrets
- Real Gitleaks reports containing unredacted secrets

The repository already ignores `.env` files and generated reports.

Before committing, check:

```powershell
git status --short
```

Search for accidental secrets:

```powershell
rg -n "OPENAI_API_KEY=|sk-proj|ghp_|AKIA" .
```

Only safe placeholders should appear.
