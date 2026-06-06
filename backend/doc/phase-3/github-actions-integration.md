# Phase 3 GitHub Actions Integration

## Purpose

Phase 3 makes CredHunter-X usable in a GitHub Actions pipeline.

The workflow is:

```text
GitHub Actions
  -> Run Gitleaks
  -> Save Gitleaks JSON report
  -> Run CredHunter-X CI command
  -> Generate JSON report
  -> Generate SARIF report
  -> Write GitHub step summary
  -> Exit with pass or fail code
```

## Implemented Files

GitHub Actions files:

- `.github/actions/credhunter-x/action.yml`
- `.github/workflows/credhunter-x.yml`

Backend CI modules:

- `Backend/app/ci/config.py`
- `Backend/app/ci/decision.py`
- `Backend/app/ci/reports.py`
- `Backend/app/ci/cli.py`

Configuration file:

- `Backend/.credhunter.yml`

## CI Command

Example:

```bash
python -m app.ci.cli \
  --gitleaks-report ../gitleaks-report.json \
  --config .credhunter.yml \
  --fail-on high \
  --json-output ../credhunter-report.json \
  --sarif-output ../credhunter-report.sarif
```

## Exit Codes

```text
0: no blocking findings
1: blocking finding detected
2: scanner, report, or configuration error
```

## Risk Thresholds

The initial Phase 3 risk logic is intentionally simple:

- Private key: critical
- AWS access key: high
- GitHub token: high
- Database URL: high
- Confidence >= 0.85: high
- Confidence >= 0.65: medium
- Otherwise: low

The `fail_on` value controls the blocking threshold.

Example:

```yaml
scan:
  fail_on: high
```

With this setting, high and critical findings fail the workflow.

## Reports

CredHunter-X generates:

- JSON report for backend or artifact use.
- SARIF report for GitHub code scanning.
- Markdown summary for `GITHUB_STEP_SUMMARY`.

## Gitleaks Workflow Behavior

The GitHub Actions workflow runs Gitleaks with `continue-on-error: true`. This allows Gitleaks to produce the raw report without failing the workflow immediately.

CredHunter-X becomes the final decision point:

```text
Gitleaks detects possible secrets
  -> CredHunter-X normalizes and scores findings
  -> CredHunter-X exits with 0, 1, or 2
```

This is important because the project goal is not only to detect possible leaks, but to reduce false positives before deciding whether the pipeline should fail.

## Backend Submission

Backend submission is implemented in Phase 4. If `backend.url` is configured in `.credhunter.yml`, the CI command submits normalized findings to:

```text
POST /api/scans
```

If `backend.url` is empty, the CI command runs in local-only mode and still generates JSON, SARIF, GitHub summary, and exit codes.
