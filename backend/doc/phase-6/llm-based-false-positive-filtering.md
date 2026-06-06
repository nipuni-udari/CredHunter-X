# Phase 6 LLM-Based False-Positive Filtering

## Purpose

Phase 6 adds optional LLM-based classification for ambiguous findings that remain after deterministic rule-based filtering.

The LLM layer is designed to reduce false positives without sending raw secrets to an external model.

## Implemented Components

Main implementation:

- `Backend/app/services/llm_filter_service.py`

Integrated into:

- `Backend/app/services/finding_service.py`
- `Backend/app/services/scan_service.py`
- `Backend/app/ci/decision.py`
- `Backend/app/api/schemas.py`
- `Backend/app/ci/config.py`

## Configuration

LLM filtering is disabled by default.

```yaml
llm:
  enabled: false
  provider: openai
  model: o4-mini
  min_confidence: 0.8
```

To enable it locally:

```powershell
Copy-Item Backend/.env.example Backend/.env
```

Then edit `Backend/.env` locally:

```text
OPENAI_API_KEY=your-rotated-key
CREDHUNTER_OPENAI_MODEL=o4-mini
CREDHUNTER_LLM_ENABLED=true
```

`Backend/.env` is ignored by git and must not be committed.

## Safety Rules

- Raw secrets are never sent to the LLM.
- Only redacted secrets and safe metadata are sent.
- Private keys are not eligible for LLM downgrade.
- If `OPENAI_API_KEY` is missing, the system falls back to deterministic Phase 5 behavior.
- If the LLM fails or returns invalid JSON, the system falls back to deterministic Phase 5 behavior.
- The LLM must return structured JSON.

## LLM Input

The LLM receives:

- Secret type.
- Redacted secret.
- File path.
- Line number.
- Detector and rule ID.
- Detector confidence.
- Entropy.
- Surrounding context if available.
- Rule-based false-positive assessment.
- Safe metadata.

The LLM does not receive:

- Raw secret value.
- Raw Gitleaks `Secret`.
- Raw Gitleaks `Match`.

## LLM Output

Expected JSON:

```json
{
  "classification": "likely_false_positive",
  "confidence": 0.86,
  "reason": "The finding appears in documentation with example-style context.",
  "recommended_action": "ignore"
}
```

Allowed classifications:

- `true_positive`
- `likely_true_positive`
- `uncertain`
- `likely_false_positive`
- `false_positive`

Allowed actions:

- `block`
- `warn`
- `ignore`
- `manual_review`
- `keep_rule_decision`

## Decision Integration

The final CI/API decision now combines:

```text
Gitleaks finding
  -> Rule-based false-positive filtering
  -> Optional LLM classification
  -> Risk adjustment
  -> Final pass/warn/ignore/fail decision
```

LLM can:

- Lower ambiguous non-critical findings to low risk.
- Ignore likely false positives when confidence is high enough.
- Escalate likely true positives to high risk.

LLM cannot:

- Downgrade private keys.
- Override deterministic critical safety rules.
- Operate without `OPENAI_API_KEY`.

## Recommended Model

The default model is:

```text
o4-mini
```

The model can be changed with:

```yaml
llm:
  model: another-model-name
```

## Testing Strategy

Phase 6 tests use fake classifiers and do not call the OpenAI API. This keeps tests deterministic and avoids spending API credits.

Live OpenAI testing should be done manually and carefully with a rotated API key.
