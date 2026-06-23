# Phase 14 LLM Pipeline Stages (Rank, Explain, Remediate)

## Purpose

Phase 14 completes the LLM pipeline proposed for the project — **LLM Classifier
→ LLM Ranker → LLM Explainer → remediation action** — by adding the three
downstream stages on top of the Phase 6 classifier. Together they form a
four-stage pipeline that runs on every Gitleaks candidate:

```text
gitleaks -> normalize -> rule filter -> LLM classify -> LLM rank -> LLM explain -> LLM remediate -> CI decision
```

## On by default, with graceful fallback

The whole pipeline is **enabled by default** (`llm.enabled: true`, and
`rank` / `explain` / `remediate` all `true`). Every stage is self-contained and
degrades gracefully:

- A stage runs only when `llm.enabled`, its own flag, and an `OPENAI_API_KEY` are
  all present.
- Without a key, or on any API/parse error, the stage is **skipped** and the
  deterministic fallback is used. The result object records `used: false` and a
  `skipped_reason`.
- The CLI runs the stages in order, each consuming the previous stage's output.

This means CredHunter-X always produces a full result offline; an API key
upgrades the output rather than being a prerequisite.

| Stage | Module | LLM output | Deterministic fallback |
| ----- | ------ | ---------- | ---------------------- |
| Classify | `services/llm_filter_service.py` | real / false-positive label + reason | rule-based false-positive filter |
| Rank | `services/llm_ranker_service.py` | refined 0–100 risk score + rationale | weighted `risk_scoring_service` score |
| Explain | `services/llm_explainer_service.py` | developer-facing rationale | rule/classification reason |
| Remediate | `services/llm_remediation_service.py` | fix steps tailored to type + location | static per-type template (`reporting/remediation.py`) |

All four share `services/llm_client.py` (one structured-output OpenAI call,
`store=False`) and the `build_llm_payload` redaction contract, so raw secrets are
never sent.

## Implemented Components

New:

- `backend/app/services/llm_client.py`
- `backend/app/services/llm_ranker_service.py`
- `backend/app/services/llm_explainer_service.py`
- `backend/app/services/llm_remediation_service.py`

Integrated into:

- `backend/app/ci/config.py` — `llm.rank`, `llm.explain`, `llm.remediate`
  (defaults `true`) + `CREDHUNTER_LLM_RANK` / `_EXPLAIN` / `_REMEDIATE` env
  overrides.
- `backend/app/ci/cli.py` — stage orchestration + `--llm-rank`, `--llm-explain`,
  `--llm-remediate` flags.
- `backend/app/ci/decision.py` — applies the ranking over the deterministic
  score and attaches explanation/remediation to each `FindingDecision`.
- `backend/app/services/risk_scoring_service.py` — `RiskScore` gains `source`
  and `rationale`; mapping helpers `risk_level_from_score` /
  `recommended_action_for_level` are shared by both rankers.
- `backend/app/reporting/markdown.py` — PR comment uses the LLM explanation and
  remediation when present.

## LLM Ranker

Input: the redacted finding, the deterministic rule-based score (as a prior), and
the classification. The model returns `{ score: 0-100, rationale }`; the risk
level and CI action are derived from that score with the same thresholds the
deterministic ranker uses, keeping downstream decision logic consistent.

Safety:

- Private keys are never scored below 90 (critical).
- An out-of-range or missing score falls back to the deterministic score.
- The applied `risk_score` carries `source: "llm"`, the `rationale`, the original
  rule components, and an `llm_ranking` component recording the delta.

## LLM Explainer

Input: the finding, classification, and risk score. Output: `{ explanation }`, a
one-to-three-sentence developer-facing rationale (plain language, grounded in
type/path/signals, never echoing the raw secret). An empty explanation is treated
as unused and the report falls back to the rule/classification reason.

## LLM Remediation

Input: the finding, classification, risk score, and the static template steps.
Output: `{ steps: [...] }`, two to four ordered, context-specific actions
(revoke/rotate the specific credential, remove from file + history, move to the
right secret store). If no usable steps are returned, the per-type template is
used.

## Output

Each finding decision may now include, in addition to `risk_score` and
`llm_filter`:

```json
{
  "llm_ranking": { "score": 88, "risk_level": "critical", "rationale": "…", "used": true },
  "llm_explanation": { "explanation": "Hardcoded AWS access key in application source.", "used": true },
  "llm_remediation": { "steps": ["Disable the key in IAM", "Rotate and store in a secret manager"], "used": true },
  "remediation": ["Disable the key in IAM", "Rotate and store in a secret manager"]
}
```

`remediation` is the effective list shown to developers: the LLM steps when the
stage ran, otherwise the template.

## Testing Strategy

`backend/tests/test_llm_pipeline_phase14.py` injects deterministic fake callables
(no OpenAI calls) to cover, per stage: the disabled/fallback path, a successful
run wired through `evaluate_findings`, the private-key floor, error fallback, and
end-to-end surfacing in the PR comment. As with Phase 6, live OpenAI runs are
done manually with a rotated key.
