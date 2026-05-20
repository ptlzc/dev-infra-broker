from enum import StrEnum
from typing import Annotated

from fastapi import FastAPI, HTTPException, Path
from pydantic import BaseModel, Field


app = FastAPI(
    title="Dev Infra Broker",
    version="0.1.0",
    description=(
        "Internal broker for k3s deployment automation. "
        "Write-capable endpoints are disabled until authn/authz/audit backends are configured."
    ),
)


class Generator(StrEnum):
    RANDOM_BASE64 = "random-base64"
    RANDOM_HEX = "random-hex"
    RANDOM_PASSWORD = "random-password"


class GeneratedSecretSpec(BaseModel):
    generator: Generator
    bytes: int | None = Field(default=None, ge=16, le=128)
    length: int | None = Field(default=None, ge=16, le=128)


class RuntimeSecretEnsureRequest(BaseModel):
    cluster: str = Field(pattern=r"^[a-z0-9-]+$")
    namespace: str = Field(pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
    serviceAccountName: str = Field(pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
    destinationSecretName: str = Field(pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
    generated: dict[str, GeneratedSecretSpec] = Field(default_factory=dict)
    requiredExisting: list[str] = Field(default_factory=list)


class RuntimeSecretEnsureResponse(BaseModel):
    ok: bool
    destinationSecretName: str
    generatedWritten: list[str]
    requiredExistingPresent: list[str]
    requiredExistingMissing: list[str]


class GitHubActionsSecretSyncRequest(BaseModel):
    cluster: str = Field(pattern=r"^[a-z0-9-]+$")
    secretSet: str = Field(pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
    keys: list[str] = Field(min_length=1)


class GitHubActionsSecretSyncResponse(BaseModel):
    ok: bool
    repository: str
    synced: list[str]
    missing: list[str]


@app.get("/healthz", tags=["system"])
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/v1/capabilities", tags=["capabilities"])
def capabilities() -> dict[str, object]:
    return {
        "service": "dev-infra-broker",
        "mode": "skeleton-disabled-writes",
        "runtimeSecretSets": {
            "enabled": False,
            "generators": [item.value for item in Generator],
            "returnsSecretValues": False,
        },
        "githubActionsSecrets": {
            "enabled": False,
            "returnsSecretValues": False,
        },
        "rules": [
            "Broker clients never receive Vault paths or Vault tokens.",
            "Broker responses never include secret values.",
            "Write-capable endpoints require authn, authz, and audit before enablement.",
        ],
    }


@app.post(
    "/v1/runtime-secret-sets/ensure",
    response_model=RuntimeSecretEnsureResponse,
    tags=["runtime-secrets"],
)
def ensure_runtime_secret_set(_: RuntimeSecretEnsureRequest) -> RuntimeSecretEnsureResponse:
    raise HTTPException(
        status_code=501,
        detail="Runtime secret writes are disabled until authn/authz/audit backends are configured.",
    )


@app.post(
    "/v1/github/repositories/{owner}/{repo}/actions-secrets/sync",
    response_model=GitHubActionsSecretSyncResponse,
    tags=["github"],
)
def sync_github_actions_secrets(
    owner: Annotated[str, Path(pattern=r"^[A-Za-z0-9_.-]+$")],
    repo: Annotated[str, Path(pattern=r"^[A-Za-z0-9_.-]+$")],
    _: GitHubActionsSecretSyncRequest,
) -> GitHubActionsSecretSyncResponse:
    _ = f"{owner}/{repo}"
    raise HTTPException(
        status_code=501,
        detail="GitHub Actions secret sync is disabled until authn/authz/audit backends are configured.",
    )

