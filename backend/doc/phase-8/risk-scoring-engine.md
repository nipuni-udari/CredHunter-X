# Phase 8 Risk Scoring Engine

## Purpose

Phase 8 replaces the earlier simple risk mapping with a weighted scoring engine.

The scoring engine combines detector confidence, secret type, file context, rule-based false-positive signals, LLM classification, and optional validation results into a single numeric score.

## Implemented Components

Main implementation:

- `backend/app/services/risk_scoring_service.py`

Integrated into:

- `backend/app/ci/decision.py`
- `backend/app/ci/reports.py`
- `backend/app/ci/cli.py`
- `backend/app/services/scan_service.py`

## Scoring Formula

The score is calculated from weighted components:

```text
risk_score =
  detector_score
+ secret_type_weight
+ file_context_weight
+ validation_weight
+ git_exposure_weight
+ llm_weight
- false_positive_weight
```

The final score is clamped to:

```text
0-100
```

## Score Bands

```text
0-29: low
30-59: medium
60-79: high
80-100: critical
```

## Default Actions

```text
low: pass
medium: warn
high: manual_review
critical: fail
```

The `fail_on` setting still controls the blocking threshold.

Example:

```yaml
scan:
  fail_on: high
```

With this setting, high and critical findings fail the workflow.

Example:

```yaml
scan:
  fail_on: critical
```

With this setting, high findings require manual review, while critical findings fail the workflow.

## Risk Components

### Detector Score

Detector confidence contributes up to 30 points.

Example:

```text
confidence 0.90 -> +27
```

### Secret Type Weight

Examples:

```text
private_key: +50
aws_access_key: +40
github_token: +35
database_url: +30
jwt: +20
generic_high_entropy_secret: +15
```

### File Context Weight

Examples:

```text
.env file: +20
production/deployment path: +20
CI/CD context: +10
docs/examples/tests path: -25
Markdown documentation file: -20
```

### False-Positive Filter Weight

Examples:

```text
false_positive: -60
likely_false_positive: -45
uncertain: -10
```

Provider-formatted secrets in uncertain documentation/test contexts are kept at least medium risk unless the LLM confidently classifies them as likely false positives.

### LLM Weight

Examples:

```text
true_positive: +40
likely_true_positive: +30
likely_false_positive: -35
false_positive: -50
```

Private keys cannot be downgraded by LLM classification.

### Validation Weight

Examples:

```text
active credential: +50
invalid/expired/local-only: -45
unverified external credential: +10
```

## Output

Every finding decision now includes:

```json
{
  "risk_score": {
    "score": 72,
    "risk_level": "high",
    "recommended_action": "manual_review",
    "components": [
      {
        "name": "detector_score",
        "value": 27,
        "reason": "Detector confidence is 0.90."
      }
    ]
  }
}
```

The CI summary now includes:

- Blocking findings.
- Manual review findings.
- Warning findings.
- Ignored findings.
- Risk score per finding.

## Safety Rules

- Private keys have a minimum critical score.
- LLM classifications below the configured confidence threshold do not affect score.
- Active validation can push a finding to critical.
- Invalid, expired, or local-only validation can reduce risk.
- Obvious rule-based false positives can still be ignored.
- High findings below the blocking threshold become `manual_review`, not silent passes.
