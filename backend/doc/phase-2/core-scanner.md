# Phase 2 Core Scanner Implementation

## Purpose

Phase 2 introduces the core scanner layer for CredHunter-X. This layer is responsible for accepting raw scanner output, normalizing findings, redacting secrets, hashing secrets for deduplication, and producing safe structured JSON for later filtering and scoring phases.

## Implemented Components

The scanner package is located in:

```text
Backend/app/scanner/
```

Implemented modules:

- `models.py`: raw and normalized finding data models.
- `redaction.py`: secret redaction and HMAC-SHA256 hashing.
- `entropy.py`: Shannon entropy utilities.
- `normalizer.py`: conversion from raw findings to safe normalized findings.
- `gitleaks_parser.py`: Gitleaks JSON and SARIF report parsing.
- `source_scanner.py`: lightweight fallback scanner for local development.
- `cli.py`: command-line entry point.

## Gitleaks Integration

Gitleaks remains the first-stage scanner. CredHunter-X consumes Gitleaks output and converts it into the internal normalized format.

Supported input formats:

- Gitleaks JSON report.
- Gitleaks SARIF report.

Example:

```bash
python -m app.scanner.cli normalize-gitleaks --input gitleaks-report.json --output normalized-findings.json
```

## Local Fallback Scanner

A lightweight fallback scanner is included for development and early testing.

Example:

```bash
python -m app.scanner.cli scan-path --path . --output local-findings.json
```

The fallback scanner supports:

- AWS access key patterns.
- GitHub token patterns.
- Private key blocks.
- Database URLs.
- JWT-like values.
- Generic high-entropy assignments.

This fallback scanner is not intended to replace Gitleaks. It is useful for local development and early integration testing.

## Normalized Finding Format

Example output:

```json
{
  "finding_id": "8b6df17f9c2a1c4d5e6f7890",
  "detector": "gitleaks",
  "secret_type": "github_token",
  "file_path": "src/config.ts",
  "line_number": 42,
  "redacted_secret": "ghp_****abcd",
  "secret_hash": "hmac-sha256:...",
  "confidence": 0.85,
  "entropy": 4.7,
  "commit_sha": "abc123",
  "rule_id": "github-pat",
  "description": "GitHub personal access token",
  "context_before": null,
  "context_after": null,
  "source": "gitleaks_json",
  "metadata": {}
}
```

## Security Rules

The Phase 2 scanner follows these rules:

- Raw secrets are held only in transient `RawFinding` objects.
- Normalized output does not include raw secrets.
- Redacted secrets are safe to show in reports.
- Secret hashes use HMAC-SHA256.
- Raw Gitleaks `Secret` and `Match` fields are not copied into metadata.

## Next Phase Dependency

Phase 3 can use this scanner layer inside GitHub Actions:

```text
GitHub Actions
  -> Run Gitleaks
  -> Save JSON/SARIF report
  -> Normalize report using CredHunter-X scanner
  -> Send normalized findings to backend
```
