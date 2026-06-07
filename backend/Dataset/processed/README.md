# CredData Python Evaluation JSONL

Generated from the Python-only CredData subset in this folder.

## Files

- `creddata_python_eval.jsonl` - one labelled candidate per line.
- `creddata_python_eval.summary.json` - record and label counts.

## Label Mapping

- `T` -> `true_secret`
- `F` -> `false_positive`
- `X` -> `false_positive`

## Key Fields

- `candidate_id` - stable ID derived from the CredData row ID.
- `repo_url` / `commit_sha` - source repository and commit from `snapshot.json`.
- `file_path` - generated CredData file path.
- `line_start` / `line_end` - labelled line span.
- `category` - CredData credential category.
- `ground_truth` - normalized label for evaluation.
- `redacted_secret` - safe marker when value offsets are available.
- `secret_features` - length and entropy of the obfuscated candidate value when available.
- `target_line_redacted` - labelled line with the candidate replaced by a marker when offsets are available.
- `code_context_redacted` - numbered code context around the finding.
- `signals` - simple static signals useful for LLM prompts and ablation experiments.

The source values in CredData are already obfuscated, but this JSONL still redacts candidate values before use in LLM prompts.
