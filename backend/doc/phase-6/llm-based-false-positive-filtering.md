# Phase 6 LLM-Based False-Positive Filtering

> **Note (Phase 14):** This classifier is now **stage 1 of the four-stage LLM
> pipeline** (classify → rank → explain → remediate; see
> `doc/phase-14/llm-pipeline-stages.md`). The whole pipeline is **on by default**
> and degrades gracefully — every stage, including this one, is skipped when no
> `OPENAI_API_KEY` is present and the deterministic engine takes over. The
> "disabled by default" wording below is historical; the runtime default is now
> `llm.enabled: true`.

## Purpose

Phase 6 adds LLM-based classification for ambiguous findings that remain after deterministic rule-based filtering.

The LLM layer is designed to reduce false positives without sending raw secrets to an external model.

## Implemented Components

Main implementation:

- `backend/app/services/llm_filter_service.py`

Integrated into:

- `backend/app/services/finding_service.py`
- `backend/app/services/scan_service.py`
- `backend/app/ci/decision.py`
- `backend/app/api/schemas.py`
- `backend/app/ci/config.py`

## Configuration

The LLM pipeline (including this classifier) is enabled by default and no-ops without an API key.

```yaml
llm:
  enabled: true
  provider: openai
  model: o4-mini
  min_confidence: 0.8
  workflow: single   # single | agentic
  rank: true         # downstream stages, see phase-14
  explain: true
  remediate: true
```

To enable it locally:

```powershell
Copy-Item backend/.env.example backend/.env
```

Then edit `backend/.env` locally:

```text
OPENAI_API_KEY=your-rotated-key
CREDHUNTER_OPENAI_MODEL=o4-mini
CREDHUNTER_LLM_ENABLED=true
```

`backend/.env` is ignored by git and must not be committed.

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

## Workflows (single vs agentic) — RQ2

The LLM step supports two workflows, selected by `llm.workflow`:

```yaml
llm:
  enabled: true
  workflow: single   # or: agentic
```

- `single` — one prompt returns classification + justification together.
- `agentic` — two steps: step 1 classifies, step 2 re-checks the evidence,
  may revise the label, then justifies. Each result records
  `metadata.preliminary_classification` and `metadata.label_revised` so the
  ablation can measure how often step 2 changes the verdict.

Both are OpenAI callables behind the same `classifier` interface
(`classifier_for_workflow`), so they are swappable and individually testable.

## Research Harnesses

| Research question | Module | What it produces |
| ----------------- | ------ | ---------------- |
| RQ1: LLM vs baseline vs rules | `app/evaluation/llm_experiment.py` | precision/recall/F1 + FP-reduction per arm (`baseline`, `rules_only`, `llm_single`, `llm_agentic`) |
| RQ2: single vs agentic | `app/evaluation/llm_experiment.py` | per-arm metrics, label-revision rate, single-vs-agentic agreement |
| RQ3: explanation quality | `app/evaluation/explanation_quality.py` | per-explanation checks + aggregate quality score, optional LLM-as-judge |

Run the ablation:

```powershell
python -m app.evaluation.llm_experiment --balanced --limit 200 --output reports/ablation.json
```

The LLM arms reuse `LLMFilterService`, so the cost-saving skip (rule already
settled the finding, private key, no API key) applies exactly as in production.
Without `OPENAI_API_KEY` the LLM arms skip and fall back to rule decisions.

## Testing Strategy

Phase 6 and the RQ2/RQ3 harness tests use fake classifiers / a fake judge and do
not call the OpenAI API. This keeps tests deterministic and avoids spending API
credits. The agentic orchestration is unit-tested by mocking the JSON call.

Live OpenAI runs (real RQ1/RQ2/RQ3 numbers) should be done manually with a
rotated API key, using `--limit` and `--balanced` to control cost.
