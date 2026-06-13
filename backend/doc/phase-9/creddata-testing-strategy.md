# Phase 9 CredData Testing Strategy

## Purpose

Phase 9 uses the local **CredData** dataset under `backend/Dataset` as the controlled benchmark dataset for testing.

This phase does not calculate final research metrics. Final precision, recall, F1, and false-positive reduction belong to Phase 10.

## Dataset Location

```text
backend/Dataset
```

Important files:

```text
backend/Dataset/processed/creddata_python_eval.jsonl
backend/Dataset/processed/creddata_python_eval.summary.json
backend/Dataset/processed/creddata_python_eval.enriched.jsonl
```

Current processed summary:

```text
records: 4387
true_secret: 654
false_positive: 3733
```

## Implemented Components

Dataset loader:

```text
backend/app/evaluation/creddata_loader.py
```

Phase 9 runner:

```text
backend/app/evaluation/phase9_runner.py
```

Tests:

```text
backend/tests/test_creddata_phase9.py
```

## What Phase 9 Tests

Phase 9 verifies:

- CredData files exist and can be loaded.
- Processed summary counts match the expected label distribution.
- CredData records can be converted into safe `NormalizedFinding` objects.
- Ground-truth labels are kept for testing but not leaked into LLM prompts.
- The backend API can accept CredData-derived findings.
- CI decision logic can process a balanced CredData sample.
- Risk scores are generated for CredData-derived findings.
- Raw secret fields are not introduced into serialized findings.

## Why Labels Are Not Sent To The LLM

CredData contains `ground_truth` labels. These labels are useful for testing and Phase 10 evaluation, but they must not be included in model prompts.

The LLM prompt builder now strips:

```text
ground_truth
ground_truth_raw
label
secret
raw_secret
matched_text
```

This prevents label leakage during LLM classification tests.

## How To Run Phase 9 Dataset Check

Balanced sample:

```bash
python -m app.evaluation.phase9_runner --balanced --limit 20
```

Write a report:

```bash
python -m app.evaluation.phase9_runner --balanced --limit 20 --output tests/fixtures/generated/phase9-creddata-check.json
```

## Relationship To Phase 10

Phase 9 proves the system can safely and repeatedly process CredData.

Phase 10 will use the same loader to calculate:

- Precision.
- Recall.
- F1 score.
- False-positive rate.
- False-negative rate.
- False-positive reduction.
- Manual review reduction.
