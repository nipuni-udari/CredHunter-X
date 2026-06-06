# Phase 1 Requirements

## Purpose

Phase 1 defines the initial scope and requirements for CredHunter-X. The project is a Git leak detection and false-positive filtering tool designed to run in **GitHub Actions**.

CredHunter-X will use **Gitleaks as the first-stage scanner** and add backend intelligence for filtering, classification, risk scoring, and CI/CD decision-making.

## Project Goal

The goal is to reduce false positives in Git leak detection while preserving high recall for real credential leaks.

CredHunter-X should:

- Detect potential secrets in GitHub repositories.
- Run automatically inside GitHub Actions.
- Use Gitleaks for raw secret detection.
- Normalize Gitleaks findings into a consistent internal format.
- Apply rule-based false-positive filtering.
- Use LLM-based classification for ambiguous findings.
- Calculate risk scores.
- Decide whether a GitHub Actions workflow should pass, warn, require review, or fail.
- Store scan results and finding metadata in MongoDB.

## In Scope

- GitHub Actions integration.
- Optional local CLI mode for developer testing.
- Gitleaks JSON/SARIF parsing.
- Finding normalization.
- Redaction and hashing of secret values.
- Rule-based false-positive filtering.
- LLM-assisted classification for ambiguous findings.
- Risk scoring.
- MongoDB-backed scan and finding storage.
- JSON report output.
- SARIF report support.
- Pull request summary output.
- CI pass/warn/fail decision logic.

## Out of Scope for Initial Version

- GitLab CI integration.
- Jenkins integration.
- Complex frontend dashboard.
- Multi-tenant SaaS billing or organization management.
- Full production secret rotation automation.
- Large-scale enterprise policy engine.
- Provider-specific validation for every token type.

## Target Platform

The only supported CI/CD platform for this version is:

- GitHub Actions

The GitHub Actions workflow should support:

- Pull request scans.
- Push scans.
- Manual workflow dispatch scans.
- Configurable failure threshold.
- JSON and SARIF artifact generation.

## Scan Modes

CredHunter-X should support the following scan modes:

### Changed Files Scan

Scans only files changed in a pull request.

Recommended for:

- Fast pull request checks.
- Developer feedback.
- Reducing CI execution time.

### Full Repository Scan

Scans the current repository working tree.

Recommended for:

- Scheduled security scans.
- Initial repository onboarding.
- Manual security checks.

### Git History Scan

Scans repository commit history for leaked secrets.

Recommended for:

- Deep audits.
- Security reviews.
- Historical leak investigations.

This can be optional in the first implementation because it can be slower on large repositories.

### Pull Request Diff Scan

Scans only the diff introduced by a pull request.

Recommended for:

- Preventing new leaks.
- Avoiding repeated reporting of old findings.

## Secret Types

The system should initially support these secret categories:

- API keys.
- AWS access keys.
- GitHub tokens.
- JWTs.
- Private keys.
- Database URLs.
- OAuth tokens.
- Generic high-entropy secrets.

## Gitleaks Role

Gitleaks is used as the first-stage scanner.

Responsibilities of Gitleaks:

- Scan repository content.
- Detect known secret patterns.
- Detect high-entropy suspicious strings.
- Export findings in JSON or SARIF format.

Responsibilities of CredHunter-X:

- Run or consume Gitleaks output.
- Normalize findings.
- Add GitHub Actions metadata.
- Redact and hash detected secrets.
- Remove obvious false positives.
- Classify ambiguous findings using an LLM.
- Calculate final risk.
- Return the GitHub Actions decision.

CredHunter-X is therefore not only a Gitleaks wrapper. It is a pipeline-aware false-positive filtering and decision tool built around Gitleaks results.

## Backend Requirements

The backend should be implemented using:

- Python
- FastAPI
- MongoDB
- Redis, optional for background jobs

Backend responsibilities:

- Receive scan submissions from GitHub Actions.
- Store scan metadata.
- Store normalized findings.
- Track classification results.
- Track suppression decisions.
- Return final CI decision.

## Data Storage Requirements

MongoDB should store:

- Projects.
- Repositories.
- Scans.
- Findings.
- Classification results.
- Suppression rules.
- Audit logs.
- User feedback.

Security requirements:

- Raw secrets must not be stored.
- Raw secrets must not be logged.
- Secret values must be redacted before storage.
- Stable secret hashes should be used for deduplication.
- Access to scan results should be protected by authentication.

## GitHub Actions Decision Requirements

The final decision returned to GitHub Actions should support:

- `pass`
- `warn`
- `manual_review`
- `fail`

Suggested behavior:

```text
Low risk: pass
Medium risk: warn
High risk: manual review or fail
Critical risk: fail
```

## Configuration Requirements

The tool should support a repository configuration file.

Example:

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

## Phase 1 Completion Criteria

Phase 1 is complete when:

- GitHub Actions is confirmed as the only CI/CD target.
- Gitleaks is confirmed as the first-stage scanner.
- Supported scan modes are defined.
- Supported secret types are defined.
- Backend technology choices are defined.
- MongoDB is confirmed as the storage layer.
- Success criteria for later testing and evaluation are documented.
