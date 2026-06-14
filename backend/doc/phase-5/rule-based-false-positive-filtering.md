# Phase 5 Rule-Based False-Positive Filtering

## Purpose

Phase 5 adds deterministic false-positive filtering before the future LLM filtering phase.

The goal is to remove obvious false positives without using an LLM and without downgrading dangerous findings such as private keys.

## Implemented Components

Main implementation:

- `backend/app/services/false_positive_filter.py`

Integrated into:

- `backend/app/ci/decision.py`
- `backend/app/scanner/normalizer.py`

## Filter Signals

The rule-based filter checks:

- Configured ignored paths.
- Literal placeholder / dummy values (in the secret value itself).
- Local-only database URLs.
- Repeated, sequential, or single-character dummy strings.
- UUIDs and digest-shaped hex strings (md5/sha1/sha256/...).
- Findings with no extractable secret value (not a credential).
- Generic findings whose value is too short or whose entropy is below the
  real-secret range (`filters.min_secret_length`, `filters.min_entropy`).
- Documentation, example, test, fixture, mock, and sample paths.

### Generic-only vs all-type rules

Entropy, length, UUID, and hash heuristics apply **only** to
`generic_secret` / `generic_high_entropy_secret` findings. Provider tokens
(`github_token`, `aws_access_key`, `jwt`, `oauth_token`, `database_url`) have
known formats and can legitimately be short or low-entropy, so they are never
downgraded by those heuristics. Path-based context never auto-ignores on its
own, because real secrets frequently live in test files.

## Configuration

```yaml
filters:
  allow_placeholders: true
  min_entropy: 1.8          # generic findings below this are likely false positives
  min_secret_length: 4      # generic findings shorter than this are likely false positives
  require_secret_value: true # findings with no extractable value are likely false positives
```

## Measured Impact (CredData, 4,387 candidates)

Rule-based layer only (no LLM), via `python -m app.evaluation.phase10_runner`:

| Metric        | Raw scanner | Rule-based filter |
| ------------- | ----------- | ----------------- |
| Precision     | 0.149       | 0.604             |
| Recall        | 1.000       | 0.962             |
| F1            | 0.259       | 0.742             |
| False positives removed | —  | 88.9%             |

The filter removes ~89% of false positives while preserving ~96% recall on
real leaked credentials.

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
