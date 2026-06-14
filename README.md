# CredHunter-X

LLM-assisted secret detection and false-positive reduction for source code.

CredHunter-X runs [Gitleaks](https://github.com/gitleaks/gitleaks) as a
high-recall first-stage scanner, then reduces its false positives with a
deterministic rule layer and an optional LLM classifier that also explains each
decision. On the CredData Python benchmark the rule layer alone removes **~89%
of false positives while preserving ~96% recall** on real leaked credentials.

```
gitleaks  →  normalize  →  rule filter  →  (optional) LLM filter  →  risk score  →  CI decision
```

## Use it in your repo (GitHub Actions)

Add one step to your workflow. No server to host — the optional LLM tier calls
OpenAI directly, so all you add for it is a repository secret.

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
          # enable_llm: "true"   # uncomment to turn on the LLM tier
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}   # only needed if enable_llm is true

      - uses: actions/upload-artifact@v4   # download the full JSON + PR-comment reports
        if: always()
        with:
          name: credhunter-report
          path: |
            credhunter-report.json
            credhunter-pr-comment.md

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
| `credhunter-report` **artifact** | Full `credhunter-report.json` + markdown to download |

The single line in the step **log** (`action=…, findings=…`) is just a summary —
the detail is on the **Summary** page, not in the log.

### Do I need an OpenAI key or a hosted backend?

No to both, unless you want the extras:

| You want… | You need… |
| --------- | --------- |
| Gitleaks + rule-based filtering (the 89% / 96% result) | nothing extra |
| The LLM classifier + explanations | an `OPENAI_API_KEY` secret and `enable_llm: "true"` |
| Persistent scan history, dashboard, triage/feedback | the self-hosted backend (`docker-compose up`) |

The LLM is an HTTPS call to OpenAI, not to a CredHunter server. The bundled
FastAPI/Mongo/Redis backend is only for storage and the dashboard.

### Inputs

| Input | Default | Description |
| ----- | ------- | ----------- |
| `scan_path` | `.` | Path within the repo to scan. |
| `config` | `.credhunter.yml` | Optional config file at your repo root. |
| `fail_on` | `high` | Risk level that fails the job (`low`/`medium`/`high`/`critical`). |
| `enable_llm` | `false` | Run the optional LLM classifier. |
| `llm_workflow` | `single` | LLM workflow (`single` or `agentic`). |

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
  enabled: false            # also toggled by enable_llm / OPENAI_API_KEY
  workflow: single          # single | agentic
  model: o4-mini
```

## Use it locally (no Actions)

```bash
gitleaks detect --report-format json --report-path gitleaks-report.json
cd backend && pip install -r requirements.txt
python -m app.ci.cli --gitleaks-report ../gitleaks-report.json --fail-on high
# add --enable-llm (with OPENAI_API_KEY set) for the LLM tier
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
