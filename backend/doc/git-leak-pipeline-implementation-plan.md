# CredHunter-X Git Leak Pipeline Implementation Plan

## 1. Project Feasibility

This project is technically possible and is a strong next-level direction for Git leak detection. The main idea is to integrate Git secret scanning into a CI/CD pipeline and add a false-positive filtering layer before findings reach developers or block deployments.

Traditional Git leak scanners are good at finding suspicious strings, but they often produce false positives from documentation, test files, dummy credentials, hashes, examples, and placeholder values. CredHunter-X can improve this by combining:

- High-recall secret detection.
- CI/CD pipeline integration.
- Rule-based false-positive filtering.
- LLM-based context classification.
- Risk scoring.
- Optional secret validation.
- Developer feedback and suppression workflows.

The research contribution should focus on reducing false positives while preserving high recall for real leaked credentials.

## 2. Recommended Technology Stack

### Backend

Recommended backend language: **Python**

Recommended backend framework: **FastAPI**

Reasons:

- Python is well suited for LLM integration, machine learning workflows, evaluation scripts, and security automation.
- FastAPI provides high-performance async APIs with automatic OpenAPI documentation.
- Python has strong support for background jobs, metrics, data processing, and prompt evaluation.
- It is practical for a research/FYP project because the implementation can evolve quickly.

Alternative:

- Go can be used later for a faster standalone scanner CLI, but Python is better for the first complete system because the backend, LLM filtering, evaluation, and scanner logic can live in one ecosystem.

Recommended initial stack:

- Python
- FastAPI
- MongoDB
- Redis
- Celery or RQ for background processing
- Docker and Docker Compose
- GitHub Actions for pipeline integration

MongoDB is suitable for this system because scan findings are naturally document-shaped. Each finding can contain nested detector metadata, GitHub Actions metadata, LLM classification details, risk scoring signals, and feedback history without requiring many relational joins.

Recommended MongoDB usage:

- Store scans as scan documents.
- Store findings as finding documents linked by `scan_id`, `project_id`, and `repository_id`.
- Add indexes for `project_id`, `repository_id`, `scan_id`, `finding_id`, `secret_hash`, `risk_level`, and `created_at`.
- Use TTL indexes only for temporary data, not for audit records.
- Never store raw secrets in MongoDB.

### Frontend

A frontend is **not required for the first version**.

The most important part of this project is the pipeline workflow and false-positive filtering engine. A frontend becomes useful if the system needs:

- A dashboard for scan history.
- Finding review and triage.
- Suppression rule management.
- Project-level security analytics.
- Manual true-positive and false-positive feedback.

If a frontend is added, the recommended framework is:

- **React + TypeScript**
- Vite for a lightweight dashboard, or Next.js if server-side rendering and more advanced routing are needed.

Recommended approach:

- Phase 1 to Phase 6: no frontend required.
- Phase 7 onward: add React + TypeScript dashboard if time allows.

## 3. High-Level System Architecture

```text
GitHub Repository / GitHub Actions Pipeline
        |
        v
CredHunter-X CLI / GitHub Action
        |
        v
Secret Detection Engine
        |
        v
Finding Normalizer
        |
        v
Backend API
        |
        +--> Rule-Based False-Positive Filter
        +--> LLM-Based Context Classifier
        +--> Optional Secret Validation Service
        +--> Risk Scoring Engine
        |
        v
Decision Output
  - Block pipeline
  - Warn only
  - Create issue
  - Mark as likely false positive
  - Require manual review
        |
        v
Reports / SARIF / Dashboard / PR Comments
```

## 4. Pipeline Workflow

The intended workflow is:

```text
Developer opens pull request
        |
CI runs CredHunter-X scanner
        |
Scanner checks changed files or full repository
        |
Potential secrets are detected
        |
Findings are sent to the backend
        |
Backend applies filtering and risk scoring
        |
Backend returns final decision
        |
CI either passes, warns, requests review, or fails
```

Recommended CI behavior:

- Fail the pipeline for high-confidence real secrets.
- Warn for medium-risk findings.
- Ignore known false positives.
- Require manual review for uncertain findings.
- Produce JSON and SARIF reports.
- Add pull request comments for new findings.

Example CI decision categories:

```text
Critical: valid cloud credential, private key, production token
High: likely real API token in source/config file
Medium: suspicious token with uncertain context
Low: docs/example/test placeholder
Ignored: known safe false positive
```

## 5. Tool Definition and Gitleaks Usage

CredHunter-X should be designed as a **security tool** that can run inside GitHub Actions. It can also provide a local CLI mode for developers, but the main project scope is pipeline-based Git leak detection with false-positive filtering.

In this design, **Gitleaks can be used as the first-stage secret detection engine**. Gitleaks is responsible for scanning repository content and producing raw potential secret findings. CredHunter-X then adds the next layer:

- Normalize Gitleaks findings into the CredHunter-X finding format.
- Add repository, pull request, and GitHub Actions metadata.
- Apply rule-based false-positive filters.
- Use an LLM to classify ambiguous findings.
- Calculate final risk scores.
- Decide whether the GitHub Actions workflow should pass, warn, require review, or fail.

Recommended use of Gitleaks:

```text
GitHub Actions
  -> Run Gitleaks scan
  -> Export Gitleaks JSON/SARIF report
  -> Send findings to CredHunter-X backend
  -> Filter false positives
  -> Return final CI decision
```

This means CredHunter-X is not just a wrapper around Gitleaks. Gitleaks performs raw detection, while CredHunter-X provides pipeline intelligence, false-positive reduction, risk scoring, reporting, and feedback workflows.

## 6. Phase-By-Phase Implementation Plan

### Phase 1: Research and Requirements

Goal: define the system scope, supported leak types, supported pipelines, and success metrics.

Tasks:

- Identify the target CI/CD platform:
  - GitHub Actions
- Keep local CLI mode as an optional developer convenience.
- Define scan modes:
  - Changed files only
  - Full repository scan
  - Git history scan
  - Pull request diff scan
- Define supported secret types:
  - API keys
  - AWS access keys
  - GitHub tokens
  - JWTs
  - Private keys
  - Database URLs
  - OAuth tokens
  - Generic high-entropy secrets
- Define Gitleaks as the first-stage scanner and baseline detection tool for comparison.
- Define success criteria for later testing and evaluation.

Deliverables:

- Requirements document: [phase-1/requirements.md](phase-1/requirements.md).
- Initial list of leak patterns: [phase-1/leak-patterns.md](phase-1/leak-patterns.md).
- Evaluation criteria: [phase-1/evaluation-criteria.md](phase-1/evaluation-criteria.md).

### Phase 2: Core Scanner

Goal: integrate or build a scanner layer that detects potential secrets with high recall.

Detection methods:

- Gitleaks JSON/SARIF output parsing.
- Regex-based detection for known credential formats.
- Entropy-based detection for random-looking strings.
- Context-based detection using variable names and file paths.
- Git metadata extraction.

Important metadata to collect:

- File path.
- Line number.
- Commit SHA.
- Branch name.
- Pull request ID, when available.
- Detector name.
- Redacted secret value.
- Secret hash.
- Surrounding code context.

Example scanner command:

```bash
credhunter scan --repo . --format json
```

Example finding:

```json
{
  "finding_id": "abc123",
  "secret_type": "github_token",
  "raw_secret_hash": "hmac_sha256_value",
  "redacted_secret": "ghp_****abcd",
  "file_path": "src/config.ts",
  "line_number": 42,
  "commit_sha": "9f2a...",
  "detector": "regex.github_token",
  "confidence": 0.91,
  "context_before": "const token =",
  "context_after": ";"
}
```

Security requirement:

- Do not store raw secrets.
- Do not print raw secrets in logs.
- Store only redacted values and cryptographic hashes.

### Phase 3: CI/CD Integration

Goal: make the scanner usable in real developer workflows.

Tasks:

- Create GitHub Action wrapper.
- Support CLI exit codes.
- Generate JSON report.
- Generate SARIF report for code scanning tools.
- Add configuration file support.
- Run Gitleaks inside the GitHub Actions workflow.
- Send Gitleaks findings to the CredHunter-X backend for filtering and scoring.

Example configuration:

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
  url: https://credhunter.example.com
```

Recommended exit code behavior:

```text
0: no blocking findings
1: blocking finding detected
2: scanner or configuration error
```

### Phase 4: Backend API

Goal: build the backend that receives findings, stores scans, classifies results, and returns CI decisions.

Suggested structure:

```text
backend/
  app/
    api/
      scan_routes.py
      finding_routes.py
      project_routes.py
    services/
      detection_service.py
      llm_filter_service.py
      risk_scoring_service.py
      validation_service.py
      suppression_service.py
    models/
      project.py
      scan.py
      finding.py
      decision.py
    workers/
      classify_worker.py
      validation_worker.py
    db/
      migrations/
```

Core backend responsibilities:

- Receive scan results.
- Normalize findings.
- Deduplicate findings.
- Apply allowlists and suppressions.
- Run deterministic false-positive filters.
- Run LLM classification for ambiguous cases.
- Assign final risk score.
- Return CI decision.
- Store audit trail.

Suggested API endpoints:

```text
POST /api/scans
GET  /api/scans/{scan_id}
POST /api/findings/classify
GET  /api/projects/{project_id}/findings
POST /api/findings/{finding_id}/suppress
POST /api/findings/{finding_id}/mark-true-positive
POST /api/findings/{finding_id}/mark-false-positive
```

Recommended MongoDB collections:

- `projects`
- `repositories`
- `scans`
- `findings`
- `classification_results`
- `suppression_rules`
- `audit_logs`
- `user_feedback`

### Phase 5: Rule-Based False-Positive Filtering

Goal: remove obvious false positives before calling the LLM.

Rule-based filters should detect:

- Placeholder values:
  - `example`
  - `dummy`
  - `changeme`
  - `your_api_key_here`
  - `000000`
- Documentation examples:
  - `README.md`
  - `docs/`
  - Markdown files
- Test fixtures:
  - `tests/`
  - `fixtures/`
  - `mock/`
- Known safe suppressions.
- Repeated fake values.
- Hashes mistaken as secrets.

Context features:

- File path.
- File extension.
- Variable name.
- Surrounding code.
- Commit message.
- Whether the file is production config.
- Whether the value appears in comments.
- Whether the value matches a real provider format.
- Whether the same value appears many times.

### Phase 6: LLM-Based False-Positive Filtering

Goal: classify ambiguous findings using code and file context.

The LLM should receive redacted and contextual information, not the raw secret.

Example LLM input:

```json
{
  "secret_type": "generic_api_key",
  "redacted_secret": "sk-****7xQ",
  "file_path": "docs/example.env",
  "line": "OPENAI_API_KEY=sk-****7xQ",
  "context": "Example configuration for local development",
  "detector_confidence": 0.78,
  "entropy_score": 4.9
}
```

Expected LLM output:

```json
{
  "classification": "likely_false_positive",
  "confidence": 0.86,
  "reason": "Appears in documentation example file with placeholder-style context.",
  "recommended_action": "warn_only"
}
```

Recommended labels:

- `true_positive`
- `likely_true_positive`
- `uncertain`
- `likely_false_positive`
- `false_positive`

Important safety rule:

- The LLM should not be the only component allowed to downgrade critical findings.
- For private keys, active cloud credentials, and production-looking tokens, require deterministic validation or manual review.

Prompt design principles:

- Use structured JSON input.
- Request structured JSON output.
- Include only minimal code context.
- Redact secrets before sending to the LLM.
- Validate the LLM response schema.
- Treat low-confidence LLM responses as uncertain.

### Phase 7: Optional Secret Validation

Goal: verify whether selected credentials are active.

Possible validation examples:

- GitHub token validation.
- AWS STS identity check.
- Slack token validation.
- Package registry token validation.

Security requirements:

- Make validation opt-in.
- Never expose secrets in logs.
- Use isolated network calls.
- Avoid destructive API calls.
- Validate only when legally and ethically allowed.

### Phase 8: Risk Scoring Engine

Goal: combine all signals into a final risk decision.

Example scoring model:

```text
risk_score =
  detector_score
+ secret_type_weight
+ file_context_weight
+ validation_weight
+ git_exposure_weight
- false_positive_weight
```

Example weights:

```text
Private key: +40
AWS key: +35
.env file: +20
Production config path: +20
Docs/example file: -25
Placeholder value: -40
Validated active token: +50
LLM says likely false positive: -20
LLM uncertain: 0
```

Decision thresholds:

```text
0-29: pass or ignore
30-59: warn
60-79: manual review
80-100: block pipeline
```

### Phase 9: Testing Strategy

Goal: prove that the system works correctly, securely, and measurably improves false-positive handling.

CredData usage:

- Use the existing **CredData** dataset only in this phase and Phase 10.
- In Phase 9, CredData is used as the controlled benchmark dataset for functional testing, integration testing, LLM classification testing, and regression testing.
- Do not use CredData as a dependency for earlier design or implementation phases.

Unit tests:

- Regex detectors.
- Entropy scoring.
- Redaction logic.
- Suppression matching.
- Risk scoring.
- LLM response parsing.

Integration tests:

- Scan a sample repository.
- Submit findings to backend.
- Receive classification.
- Generate CI output.
- Verify pipeline exit codes.

Security tests:

- Ensure raw secrets are not stored.
- Ensure raw secrets are not logged.
- Ensure API authentication works.
- Ensure users cannot access findings from other projects.
- Ensure redaction works for all supported secret types.

LLM tests:

- CredData samples labeled as known true positives and false positives.
- Prompt injection tests.
- JSON output validation.
- Regression tests for classification drift.
- Tests for uncertain classifications.

Example test dataset categories:

- Real-looking leaked token.
- Placeholder token.
- Documentation example.
- Test fixture secret.
- Revoked or expired token.
- Random hash mistaken as a secret.
- JWT-like but harmless string.
- Private key in production config.

### Phase 10: Evaluation Metrics

Goal: compare the baseline detector against CredHunter-X with false-positive filtering.

CredData usage:

- Use **CredData** as the final benchmark dataset for measuring performance.
- Run Gitleaks alone on CredData to collect baseline results.
- Run CredHunter-X with rule-based and LLM-based filtering on CredData.
- Compare the baseline results against the filtered CredHunter-X results.

Detection metrics:

- Precision.
- Recall.
- F1 score.
- False positive rate.
- False negative rate.

False-positive filtering metrics:

- Percentage of false positives removed.
- Percentage of true positives incorrectly downgraded.
- Manual review reduction.
- LLM classification accuracy.

Pipeline metrics:

- Average scan time.
- p95 scan time.
- CI failure rate.
- Number of findings per pull request.
- Developer override rate.

Security metrics:

- Mean time to detect leak.
- Mean time to remediate.
- Number of active secrets found.
- Number of repeated leaks by project.

LLM metrics:

- Classification accuracy.
- Confidence calibration.
- Cost per scan.
- Token usage per finding.
- JSON validity rate.

Most important research metric:

```text
False-positive reduction while preserving high recall.
```

Example research result:

```text
Baseline scanner:
Precision: 42%
Recall: 94%

CredHunter-X with LLM filter:
Precision: 76%
Recall: 91%
False positives reduced by 58%
```

### Phase 11: Reporting and Developer Feedback

Goal: make results useful for developers and security reviewers.

Report formats:

- JSON report.
- SARIF report.
- CI console summary.
- Pull request comment.
- Optional dashboard.

Suggested PR comment format:

```text
CredHunter-X found 2 potential secrets.

1 critical finding requires action.
1 medium finding requires review.

Critical:
- src/config.py:42
- Type: AWS access key
- Decision: block pipeline
- Reason: high-confidence cloud credential in production config
```

Developer feedback actions:

- Mark as true positive.
- Mark as false positive.
- Suppress by file path.
- Suppress by secret hash.
- Suppress by detector rule.
- Add remediation status.

### Phase 12: Deployment Process

Goal: deploy the backend and make the scanner usable in CI/CD.

Local development deployment:

- Docker Compose for:
  - FastAPI backend
  - MongoDB
  - Redis
  - Background worker
  - Optional frontend

CI deployment:

- Publish CLI package.
- Publish GitHub Action.
- Publish Docker image.

Production deployment:

- Backend in Docker.
- MongoDB Atlas or a managed MongoDB-compatible database.
- Redis queue.
- Secret manager for backend credentials.
- HTTPS API gateway.
- Role-based access control.
- Audit logging.
- Monitoring with Prometheus/Grafana or cloud-native tools.

Deployment flow:

```text
Developer PR
  -> CI tests
  -> Build Docker image
  -> Run backend tests
  -> Run scanner against test repositories
  -> Push image
  -> Deploy to staging
  -> Run smoke tests
  -> Deploy to production
```

## 7. Minimum Viable Product Scope

The recommended MVP should include:

- Python CLI or GitHub Action wrapper.
- Gitleaks integration for first-stage detection.
- Optional custom regex and entropy detection.
- Redaction and hashing.
- JSON output.
- FastAPI backend.
- MongoDB storage.
- Rule-based false-positive filtering.
- Basic LLM classifier for ambiguous findings.
- Risk score calculation.
- GitHub Actions integration.
- CredData-based testing and evaluation in Phases 9 and 10.
- Baseline vs improved metrics.

MVP should not initially include:

- Complex dashboard.
- Large-scale multi-tenant SaaS features.
- Many provider-specific validation integrations.
- Full Git history scanning for very large repositories.

## 8. Final Recommendation

Build the first version as:

```text
Python FastAPI backend
+ Gitleaks-based first-stage scanner
+ Python CLI or GitHub Action wrapper
+ GitHub Actions integration
+ rule-based filtering
+ LLM-assisted classification
+ MongoDB storage
```

Add a React + TypeScript frontend only after the scanner, backend, CI workflow, and evaluation metrics are working.

This keeps the project focused on the core research value: reducing false positives in Git leak detection without missing dangerous real secrets.
