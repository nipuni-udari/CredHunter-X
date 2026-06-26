from __future__ import annotations


REMEDIATION_BY_TYPE = {
    "private_key": [
        "Remove the private key from the repository.",
        "Rotate the key pair and revoke trust for the exposed key.",
        "Move the replacement key into a secret manager.",
    ],
    "aws_access_key": [
        "Disable or rotate the AWS access key.",
        "Review recent IAM activity for suspicious use.",
        "Store the replacement credential in GitHub Actions secrets or a cloud secret manager.",
    ],
    "aws_access_key_id": [
        "Disable or rotate the AWS access key.",
        "Review recent IAM activity for suspicious use.",
        "Store the replacement credential in GitHub Actions secrets or a cloud secret manager.",
    ],
    "github_token": [
        "Revoke or rotate the GitHub token.",
        "Remove it from source code and purge it from git history if it was committed.",
        "Store the replacement in GitHub Actions Secrets or a secret manager.",
        "Load the token from an environment variable such as GITHUB_TOKEN.",
        "Review token scope, repository access, and recent token activity.",
    ],
    "openai_api_key": [
        "Revoke or rotate the OpenAI API key.",
        "Remove it from source code and git history if it was committed.",
        "Store the replacement in GitHub Actions Secrets or a secret manager.",
        "Load it from an environment variable such as OPENAI_API_KEY.",
    ],
    "database_url": [
        "Rotate the database password if the URL points to a real service.",
        "Move the connection string into environment-specific secret storage.",
        "Confirm test/local URLs do not reach production data.",
    ],
    "oauth_token": [
        "Revoke or rotate the OAuth credential.",
        "Review granted scopes and connected application activity.",
        "Store replacement values outside source control.",
    ],
    "bearer_token": [
        "Revoke or rotate the bearer token.",
        "Review granted scopes and connected application activity.",
        "Store replacement values outside source control.",
    ],
    "jwt": [
        "Check whether the token is still valid.",
        "Rotate the signing key or revoke the session if needed.",
        "Avoid committing bearer tokens or ID tokens in fixtures.",
    ],
}


def remediation_steps(secret_type: str) -> list[str]:
    return REMEDIATION_BY_TYPE.get(
        secret_type,
        [
            "Confirm whether the value is a real credential.",
            "Rotate or revoke it if it can grant access.",
            "Move sensitive values into a secret manager or CI secret store.",
        ],
    )
