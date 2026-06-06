# Phase 1 Evaluation Criteria

## Purpose

This document defines how CredHunter-X will be evaluated later in the project. The actual benchmark dataset, **CredData**, will be used only in **Phase 9** and **Phase 10**.

Phase 1 only defines the success criteria and metrics. It does not depend on CredData during implementation.

## Evaluation Goal

The main evaluation goal is:

```text
Reduce false positives from Git leak scanning while preserving high recall for real leaked secrets.
```

The system should be compared against Gitleaks alone.

## Baseline

The baseline is:

```text
Gitleaks raw output without CredHunter-X filtering
```

CredHunter-X should be evaluated against this baseline by comparing:

- Raw Gitleaks findings.
- Findings after rule-based filtering.
- Findings after LLM-based classification.
- Final CI/CD decisions.

## Primary Metrics

### Precision

Measures how many reported findings are actually true positives.

```text
precision = true_positives / (true_positives + false_positives)
```

Higher precision means developers receive fewer false alarms.

### Recall

Measures how many actual leaks were detected.

```text
recall = true_positives / (true_positives + false_negatives)
```

Recall must remain high because missing real secrets is dangerous.

### F1 Score

Balances precision and recall.

```text
f1 = 2 * (precision * recall) / (precision + recall)
```

### False Positive Rate

Measures how often safe findings are incorrectly reported as real leaks.

```text
false_positive_rate = false_positives / (false_positives + true_negatives)
```

### False Negative Rate

Measures how often real leaks are missed or incorrectly downgraded.

```text
false_negative_rate = false_negatives / (false_negatives + true_positives)
```

## False-Positive Filtering Metrics

CredHunter-X should measure:

- Number of raw Gitleaks findings.
- Number of findings removed by rule-based filters.
- Number of findings classified by the LLM.
- Number of findings marked as likely false positives.
- Number of true positives incorrectly downgraded.
- Percentage reduction in false positives.

Important target:

```text
False positives should decrease significantly without a large recall drop.
```

## LLM Classification Metrics

The LLM layer should be evaluated using:

- Classification accuracy.
- Confidence calibration.
- JSON response validity.
- Number of uncertain classifications.
- Number of true positives incorrectly classified as false positives.
- Cost per scan.
- Token usage per finding.

Safety requirement:

```text
The LLM must not be allowed to silently ignore high-risk secrets such as private keys or active cloud credentials.
```

## Pipeline Metrics

GitHub Actions behavior should be evaluated using:

- Average scan time.
- p95 scan time.
- Number of findings per pull request.
- Number of warnings.
- Number of failed workflows.
- Number of manual review decisions.
- Developer override rate.

## Security Metrics

Security-related evaluation should include:

- Whether raw secrets are stored.
- Whether raw secrets appear in logs.
- Whether redaction works correctly.
- Whether duplicate findings are handled correctly.
- Whether high-risk findings are blocked.

Required result:

```text
Raw secrets must not be stored or logged.
```

## Expected Comparison Format

Phase 10 should report results in a table similar to:

```text
Approach                         Precision   Recall   F1     False Positives
Gitleaks only                    0.42        0.94     0.58   100
CredHunter-X rule filters        0.61        0.93     0.74   58
CredHunter-X rule + LLM filters  0.76        0.91     0.83   42
```

These numbers are examples only. Actual results should come from CredData in Phase 10.

## Success Criteria

CredHunter-X is successful if:

- It integrates with GitHub Actions.
- It uses Gitleaks as the first-stage scanner.
- It reduces false positives compared with Gitleaks alone.
- It keeps recall close to the Gitleaks baseline.
- It avoids storing or logging raw secrets.
- It produces clear pass, warn, manual review, or fail decisions.
- It provides enough evidence to explain why a finding was filtered or escalated.
