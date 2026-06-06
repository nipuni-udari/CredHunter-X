# Phase 5 Rule-Based False-Positive Filtering

## Purpose

Phase 5 adds deterministic false-positive filtering before the future LLM filtering phase.

The goal is to remove obvious false positives without using an LLM and without downgrading dangerous findings such as private keys.

## Implemented Components

Main implementation:

- `Backend/app/services/false_positive_filter.py`

Integrated into:

- `Backend/app/ci/decision.py`
- `Backend/app/scanner/normalizer.py`

## Filter Signals

The rule-based filter currently checks:

- Configured ignored paths.
- Documentation, example, test, fixture, mock, and sample paths.
- Placeholder or dummy-value indicators.
- Local-only database URLs.
- Generic high-entropy findings in docs/tests/examples.
- Repeated low-value dummy strings.

## Conservative Safety Rule

The filter does not downgrade private key findings.

```text
Private keys remain high-risk or critical even if they appear in a path that normally looks safe.
```

This prevents the deterministic filter from hiding dangerous secrets.

## Safe Secret Indicators

The scanner normalizer now adds safe metadata under:

```json
"metadata": {
  "secret_indicators": {
    "length": 32,
    "placeholder": false,
    "local_only_database_url": false,
    "repeated_or_low_value": false,
    "has_private_key_marker": false
  }
}
```

These indicators are derived while the raw secret is still transient. The raw secret itself is not stored in normalized output.

## Filter Decisions

Possible classifications:

- `false_positive`
- `likely_false_positive`
- `uncertain`
- `not_false_positive`

Possible effects:

- Ignore obvious false positives.
- Lower risk for uncertain documentation/test findings.
- Preserve high-risk findings when no safe rule matches.

## CI/API Output

Each finding decision now includes a `false_positive_filter` object:

```json
{
  "false_positive_filter": {
    "classification": "likely_false_positive",
    "ignored": true,
    "risk_override": "low",
    "reasons": [
      "Generic high-entropy finding appears in documentation, examples, tests, or fixtures."
    ],
    "signals": {
      "configured_ignored_path": false,
      "doc_or_test_path": true,
      "placeholder_value": false,
      "local_only_database_url": false,
      "repeated_or_low_value": false
    }
  }
}
```

## Examples

Ignored:

- Placeholder token in `docs/example.env`.
- Generic high-entropy value in `tests/fixtures/config.json`.
- Local database URL such as `mongodb://localhost:27017/app`.
- Findings matching configured ignored paths.

Not ignored:

- Private key blocks.
- GitHub tokens in source/config files.
- AWS keys in source/config files.
- Database URLs pointing to external hosts.

## Next Phase Dependency

Phase 6 can use this rule-based output before calling the LLM:

```text
If rule filter says obvious false positive:
  skip LLM
Else if finding is ambiguous:
  send redacted context to LLM
Else:
  keep deterministic decision
```
