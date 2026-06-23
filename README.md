# CredHunter-X

LLM-assisted secret detection, prioritisation, and remediation for source code.

CredHunter-X runs [Gitleaks](https://github.com/gitleaks/gitleaks) as a
high-recall first-stage scanner, then runs every candidate through a four-stage
LLM pipeline that classifies, ranks, explains, and proposes a fix — layered on
top of a deterministic rule/scoring engine that acts as both a fast path and a
safety net. On the CredData Python benchmark the rule layer alone removes **~89%
of false positives while preserving ~96% recall** on real leaked credentials.

```
gitleaks → normalize → rule filter → LLM classify → LLM rank → LLM explain → LLM remediate → CI decision
```

**The LLM pipeline is on by default and degrades gracefully.** Each stage runs
only when an `OPENAI_API_KEY` is available; with no key (or on any API error)
that stage is skipped and the deterministic rule filter, risk score, and
per-type remediation templates take over. So CredHunter-X always produces a full
result — adding a key upgrades the output, it is never required.

| Stage | LLM on (key present) | Fallback (no key / error) |
| ----- | -------------------- | ------------------------- |
| Classify | LLM labels each candidate real/false-positive with a reason | Deterministic rule filter decides |
| Rank | LLM refines the 0–100 risk score and prioritisation | Weighted deterministic risk score |
| Explain | LLM writes a developer-facing rationale | Rule/classification reason |
| Remediate | LLM proposes fix steps tailored to type + location | Static per-type remediation template |

## Use it in your repo (GitHub Actions)

Add one step to your workflow. No server to host — the LLM pipeline calls OpenAI
directly, so all you add to enable it is a repository secret. Omit the secret and
the deterministic engine runs on its own.

```yaml
name: Secret Scan
on: [push, pull_request]

jobs:
  credhunter:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # upload SARIF to the Security tab
      pull-requests: write     # post the findings comment on PRs
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: nipuni-udari/CredHunter-X@v1
        with:
          fail_on: high
          # The LLM pipeline is on by default; provide a key to activate it.
          # Set enable_llm: "false" to force the deterministic-only engine.
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}   # omit to run deterministic-only

      - uses: actions/upload-artifact@v4   # download the full JSON report (with per-finding remediation)
        if: always()
        with:
          name: credhunter-report
          path: credhunter-report.json

      - uses: github/codeql-action/upload-sarif@v3   # annotate file:line in the Security tab
        if: always()
        with:
          sarif_file: credhunter-report.sarif
```

The `if: always()` on the upload steps matters — without it they are skipped
exactly when the scan fails, which is when you want the reports.

### Where to see which secret was flagged

The job **fails** (exit code 1) when a finding is at or above `fail_on`. The
findings — type, redacted value, and `file:line` — show up in three places (the
raw secret is never printed; values are redacted like `ghp_****st56`):

| Where | What you get |
| ----- | ------------ |
| Run **Summary** page (top of the job) | Markdown table of every reportable finding |
| **Security → Code scanning** tab | Each finding annotated on its file and line (SARIF) |
| **PR comment** (on pull requests) | The same table, posted inline on the PR |
| `credhunter-report` **artifact** | Full `credhunter-report.json` (per-finding `remediation` steps) to download |

The single line in the step **log** (`action=…, findings=…`) is just a summary —
the detail is on the **Summary** page, not in the log.

### Do I need an OpenAI key or a hosted backend?

No to both, unless you want the extras:

| You want… | You need… |
| --------- | --------- |
| Gitleaks + rule-based filtering (the 89% / 96% result) | nothing extra — the LLM stages skip without a key |
| The full LLM pipeline (classify + rank + explain + remediate) | an `OPENAI_API_KEY` secret |
| Persistent scan history + triage/feedback (REST API) | the self-hosted backend (`docker-compose up`) |

The LLM is an HTTPS call to OpenAI, not to a CredHunter server. It is invoked
only when a key is present, so a no-key run makes no network calls and incurs no
cost. The bundled FastAPI/Mongo/Redis backend is only for storage and the
triage/feedback API.

### Inputs

| Input | Default | Description |
| ----- | ------- | ----------- |
| `scan_path` | `.` | Path within the repo to scan. |
| `config` | `.credhunter.yml` | Optional config file at your repo root. |
| `fail_on` | `high` | Risk level that fails the job (`low`/`medium`/`high`/`critical`). |
| `enable_llm` | `true` | Run the LLM pipeline (no-ops without `OPENAI_API_KEY`). Set `"false"` to force deterministic-only. |
| `llm_workflow` | `single` | Classifier workflow (`single` or `agentic`). |
| `llm_rank` | `true` | Run the LLM Ranker stage. |
| `llm_explain` | `true` | Run the LLM Explainer stage. |
| `llm_remediate` | `true` | Run the LLM Remediation stage. |

## Configuration (`.credhunter.yml`)

```yaml
scan:
  fail_on: high
filters:
  ignore_paths:
    - docs/**
    - tests/fixtures/**
  allow_placeholders: true
  min_entropy: 1.8          # generic findings below this are likely false positives
  min_secret_length: 4
llm:
  enabled: true             # whole pipeline on by default; no-ops without a key
  workflow: single          # single | agentic (classifier ablation)
  model: o4-mini
  rank: true                # LLM Ranker:    refine risk score + prioritisation
  explain: true             # LLM Explainer: developer-facing rationale
  remediate: true           # LLM Remediation: context-specific fix steps
```

Set any flag to `false` (or run without `OPENAI_API_KEY`) to fall back to the
deterministic path for that stage.

## Use it locally (no Actions)

```bash
gitleaks detect --report-format json --report-path gitleaks-report.json
cd backend && pip install -r requirements.txt
# LLM pipeline runs automatically when OPENAI_API_KEY is set; otherwise deterministic-only.
python -m app.ci.cli --gitleaks-report ../gitleaks-report.json --fail-on high
# force deterministic-only regardless of any key:
CREDHUNTER_LLM_ENABLED=false python -m app.ci.cli --gitleaks-report ../gitleaks-report.json --fail-on high
```

## Research harnesses

CredHunter-X doubles as an evaluation framework on the CredData Python subset:

```bash
python -m app.evaluation.phase10_runner                       # rules vs baseline
python -m app.evaluation.llm_experiment --balanced --limit 200  # baseline/rules/llm_single/llm_agentic
```

See `backend/doc/` for the phase-by-phase design and the RQ1/RQ2/RQ3 mapping.

## Releasing (maintainer note)

To make `@v1` resolve for consumers, tag a release on the default branch:

```bash
git tag -a v1 -m "CredHunter-X v1"
git push origin v1
```

Re-point `v1` after later fixes with `git tag -f v1 && git push -f origin v1`.
