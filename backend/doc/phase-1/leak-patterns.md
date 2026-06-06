# Phase 1 Leak Patterns

## Purpose

This document defines the initial secret categories and leak patterns CredHunter-X should support. Gitleaks will perform the first-stage detection, while CredHunter-X will normalize, filter, classify, and score the findings.

## Supported Secret Categories

### 1. API Keys

Common indicators:

- Variable names containing `api_key`, `apikey`, `apiKey`, or `x-api-key`.
- Long random-looking values.
- Values stored in `.env`, YAML, JSON, Python, JavaScript, TypeScript, or configuration files.

Example redacted form:

```text
API_KEY=****abcd
```

Risk notes:

- Higher risk when found in production configuration.
- Lower risk when found in documentation or obvious examples.

### 2. AWS Access Keys

Common indicators:

- Values beginning with `AKIA`.
- Values beginning with `ASIA`.
- Nearby terms such as `aws_secret_access_key`, `aws_access_key_id`, or `AWS_SECRET_ACCESS_KEY`.

Example redacted form:

```text
AWS_ACCESS_KEY_ID=AKIA****ABCD
```

Risk notes:

- High risk when access key and secret key appear near each other.
- Critical risk if validation confirms the credential is active.

### 3. GitHub Tokens

Common indicators:

- Tokens beginning with `ghp_`.
- Tokens beginning with `gho_`.
- Tokens beginning with `ghu_`.
- Tokens beginning with `ghs_`.
- Tokens beginning with `github_pat_`.

Example redacted form:

```text
GITHUB_TOKEN=ghp_****abcd
```

Risk notes:

- High risk in source or config files.
- Lower risk if the value appears in docs as a placeholder.

### 4. JWTs

Common indicators:

- Three base64url-like segments separated by periods.
- Header segment often starts with `eyJ`.
- Nearby names such as `jwt`, `id_token`, `access_token`, or `bearer`.

Example redacted form:

```text
JWT=eyJ****abcd
```

Risk notes:

- Some JWTs are expired or sample tokens.
- Classification should consider file path, expiration claim if decodable, and surrounding context.

### 5. Private Keys

Common indicators:

- `-----BEGIN PRIVATE KEY-----`
- `-----BEGIN RSA PRIVATE KEY-----`
- `-----BEGIN OPENSSH PRIVATE KEY-----`
- `-----BEGIN EC PRIVATE KEY-----`

Example redacted form:

```text
-----BEGIN PRIVATE KEY-----
****
-----END PRIVATE KEY-----
```

Risk notes:

- Private keys should usually be treated as high or critical severity.
- The LLM should not downgrade private key findings by itself.

### 6. Database URLs

Common indicators:

- `postgres://`
- `postgresql://`
- `mysql://`
- `mongodb://`
- `mongodb+srv://`
- `redis://`
- Username and password embedded in the URI.

Example redacted form:

```text
mongodb+srv://user:****@cluster.example.net/db
```

Risk notes:

- Higher risk if the host appears external or production-like.
- Lower risk if the credential is clearly local-only, such as localhost test credentials.

### 7. OAuth Tokens

Common indicators:

- Variable names containing `oauth`, `access_token`, `refresh_token`, `client_secret`, or `client_id`.
- Long random-looking string values.

Example redacted form:

```text
OAUTH_CLIENT_SECRET=****abcd
```

Risk notes:

- Refresh tokens are usually higher risk than short-lived access tokens.
- Client IDs alone may not be secret, but client secrets are sensitive.

### 8. Generic High-Entropy Secrets

Common indicators:

- Long strings with high Shannon entropy.
- Base64-like values.
- Hex-like values.
- Random-looking tokens assigned to sensitive variable names.

Example redacted form:

```text
SECRET_TOKEN=****abcd
```

Risk notes:

- This category may produce many false positives.
- Rule-based and LLM-based filtering are especially important here.

## False-Positive Indicators

CredHunter-X should reduce confidence when findings appear in:

- `README.md`.
- `docs/`.
- `examples/`.
- `tests/`.
- `fixtures/`.
- `mock/`.
- Comments explaining sample configuration.

CredHunter-X should also reduce confidence for values containing:

- `example`.
- `dummy`.
- `sample`.
- `changeme`.
- `placeholder`.
- `your_api_key_here`.
- `000000`.
- `abcdef`.

## High-Risk Indicators

CredHunter-X should increase confidence when findings appear in:

- `.env`.
- `.env.production`.
- `config.yml`.
- `settings.py`.
- `application.properties`.
- `secrets.yml`.
- Deployment manifests.
- CI/CD configuration files.

CredHunter-X should also increase confidence when:

- A known provider-specific format is detected.
- Multiple related credentials appear together.
- The secret appears in production-looking configuration.
- Optional validation confirms that the credential is active.

## Initial Detector Strategy

The first implementation should:

- Run Gitleaks as the primary detector.
- Parse Gitleaks JSON or SARIF output.
- Preserve the detector rule ID.
- Preserve file path and line number.
- Redact the detected secret.
- Hash the detected secret for deduplication.
- Pass normalized findings to filtering and scoring services.
