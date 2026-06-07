# Phase 7 Optional Secret Validation

## Purpose

Phase 7 adds optional validation for selected secret types.

Validation is intentionally disabled by default because it can involve sensitive raw credentials and external network calls.

## Implemented Components

Main implementation:

- `Backend/app/services/validation_service.py`

Integrated into:

- `Backend/app/api/finding_routes.py`
- `Backend/app/services/finding_service.py`
- `Backend/app/api/schemas.py`
- `Backend/app/ci/config.py`

## Endpoint

```text
POST /api/findings/validate
```

The endpoint accepts:

- A normalized finding.
- An optional raw secret.
- Validation configuration.

The raw secret is used only during the request and is not stored.

## Configuration

Validation is disabled by default:

```yaml
validation:
  enabled: false
  network_enabled: false
  providers:
    - github
    - jwt
    - database_url
  timeout_seconds: 5
```

Environment overrides:

```text
CREDHUNTER_VALIDATION_ENABLED=false
CREDHUNTER_VALIDATION_NETWORK_ENABLED=false
```

## Supported Validators

### GitHub Token

Provider:

```text
github
```

Behavior:

- Requires raw token.
- Requires `validation.enabled=true`.
- Requires `validation.network_enabled=true`.
- Sends a read-only request to `https://api.github.com/user`.
- Interprets HTTP 200 as valid.
- Interprets HTTP 401/403 as invalid.

### JWT

Provider:

```text
jwt
```

Behavior:

- Decodes the JWT payload locally.
- Checks the `exp` claim if present.
- Does not verify the signature.
- Does not use the network.

### Database URL

Provider:

```text
database_url
```

Behavior:

- Parses the URL locally.
- Marks localhost/127.0.0.1 URLs as local-only.
- Does not connect to the database.
- Does not use the network.

## Safety Rules

- Validation is opt-in.
- Network validation is separately opt-in.
- Raw secrets are never stored.
- Raw secrets are not logged.
- External validation calls must be read-only.
- Destructive provider API calls are not allowed.

## Example Request

```json
{
  "finding": {
    "detector": "gitleaks",
    "secret_type": "github_token",
    "file_path": "src/config.py",
    "line_number": 7,
    "redacted_secret": "ghp_****7890",
    "secret_hash": "hmac-sha256:test",
    "confidence": 0.9,
    "source": "gitleaks_json"
  },
  "raw_secret": "transient-token-value",
  "config": {
    "validation": {
      "enabled": true,
      "network_enabled": true,
      "providers": ["github"],
      "timeout_seconds": 5
    }
  }
}
```

## Response

```json
{
  "provider": "github",
  "status": "valid",
  "active": true,
  "reason": "GitHub token authenticated successfully.",
  "checked": true,
  "network_used": true,
  "metadata": {}
}
```
