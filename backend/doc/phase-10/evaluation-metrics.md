# Phase 10 Evaluation Metrics

## Purpose

Phase 10 evaluates CredHunter-X against the labeled CredData Python subset.

CredData provides ground-truth labels:

```text
true_secret
false_positive
```

The evaluator compares CredHunter-X decisions against these labels and calculates standard classification metrics.

## Implemented Components

Metrics:

```text
backend/app/evaluation/metrics.py
```

Evaluation runner:

```text
backend/app/evaluation/phase10_runner.py
```

Tests:

```text
backend/tests/test_evaluation_phase10.py
```

## Decision Mapping

For `true_secret` records:

```text
Correct: warn, manual_review, fail
Incorrect: pass, ignore
```

For `false_positive` records:

```text
Correct: pass, ignore
Incorrect: warn, manual_review, fail
```

## Baseline Modes

By default, the baseline represents raw scanner triage load:

```text
Baseline reports every CredData candidate as a finding.
```

This means:

- Every `true_secret` is a baseline true positive.
- Every `false_positive` is a baseline false positive.
- Baseline recall is 1.0.
- Baseline precision depends on the true/false label distribution.

CredHunter-X is expected to reduce false positives while preserving recall.

If a Gitleaks JSON/SARIF report is available, the evaluator can use it as the baseline:

```bash
python -m app.evaluation.phase10_runner --gitleaks-report gitleaks-report.json
```

The evaluator matches Gitleaks findings to CredData records by file path and line number.

## Metrics

The evaluator calculates:

- Precision.
- Recall.
- F1 score.
- Accuracy.
- False positive rate.
- False negative rate.
- False-positive reduction.
- Manual review reduction.
- Action counts.
- Label/action counts.

## Run Evaluation

Balanced sample:

```bash
python -m app.evaluation.phase10_runner --balanced --limit 20
```

Full CredData Python subset:

```bash
python -m app.evaluation.phase10_runner --output tests/fixtures/generated/phase10-full-evaluation.json
```

With Gitleaks report:

```bash
python -m app.evaluation.phase10_runner --gitleaks-report gitleaks-report.json --output tests/fixtures/generated/phase10-gitleaks-evaluation.json
```

Limited sequential sample:

```bash
python -m app.evaluation.phase10_runner --limit 100 --output tests/fixtures/generated/phase10-sample-evaluation.json
```

## Output Example

```json
{
  "metrics": {
    "baseline": {
      "precision": 0.149,
      "recall": 1.0
    },
    "credhunter_x": {
      "precision": 0.71,
      "recall": 0.89
    },
    "improvement": {
      "false_positive_reduction": 0.62,
      "f1_delta": 0.31
    }
  }
}
```

Actual values depend on the selected sample and current scoring/filter rules.

## Current Full-Dataset Result

Using the default raw-candidate baseline on the full processed CredData Python subset:

```text
records: 4387
true_secret: 654
false_positive: 3733

baseline precision: 0.149077
baseline recall: 1.0
baseline F1: 0.259473

CredHunter-X precision: 0.041047
CredHunter-X recall: 0.088685
CredHunter-X F1: 0.05612
false-positive reduction: 0.637021
```

This result shows the current rules remove many false positives, but they also over-filter many CredData true secrets. That is useful research evidence: Phase 10 exposes where the rules need tuning before final reporting.
