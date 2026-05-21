from enum import StrEnum
import os
from typing import Annotated

import httpx
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

PLATFORM_SECRET_KEYS = [
    "REGISTRY_USERNAME",
    "REGISTRY_PASSWORD",
    "REGISTRY_URL",
    "REGISTRY_NAMESPACE",
    "GH_PAT",
]


def _vault_settings() -> tuple[str, str, str]:
    address = os.getenv("VAULT_ADDR", "").rstrip("/")
    mount = os.getenv("VAULT_KV_MOUNT", "k3s-kv").strip("/")
    path = os.getenv("VAULT_PLATFORM_SECRET_PATH", "platform").strip("/")
    if not address:
        raise HTTPException(
            status_code=503,
            detail="Vault backend is not configured for dev-infra-broker.",
        )
    return address, mount, path


def _vault_token() -> str:
    static_token = os.getenv("VAULT_TOKEN")
    if static_token:
        return static_token

    address, _, _ = _vault_settings()
    role = os.getenv("VAULT_K8S_ROLE", "dev-infra-broker-platform-reader")
    auth_mount = os.getenv("VAULT_K8S_AUTH_MOUNT", "kubernetes").strip("/")
    jwt_path = os.getenv(
        "VAULT_K8S_JWT_PATH",
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
    )
    try:
        with open(jwt_path, encoding="utf-8") as token_file:
            jwt = token_file.read().strip()
    except OSError as exc:
        raise HTTPException(status_code=503, detail="Kubernetes service account token is unavailable.") from exc

    try:
        response = httpx.post(
            f"{address}/v1/auth/{auth_mount}/login",
            json={"role": role, "jwt": jwt},
            timeout=5.0,
        )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="Vault Kubernetes login failed.") from exc
    if response.status_code in {401, 403}:
        raise HTTPException(status_code=503, detail="Vault Kubernetes login is denied.")
    if response.status_code >= 400:
        raise HTTPException(status_code=502, detail="Vault Kubernetes login returned an error.")
    token = response.json().get("auth", {}).get("client_token")
    if not token:
        raise HTTPException(status_code=502, detail="Vault Kubernetes login returned no client token.")
    return token


def _read_vault_kv2_secret(mount: str, path: str) -> dict[str, object]:
    address, _, _ = _vault_settings()
    token = _vault_token()
    url = f"{address}/v1/{mount}/data/{path}"
    try:
        response = httpx.get(url, headers={"X-Vault-Token": token}, timeout=5.0)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="Vault backend request failed.") from exc
    if response.status_code == 404:
        return {}
    if response.status_code in {401, 403}:
        raise HTTPException(status_code=503, detail="Vault backend access is denied.")
    if response.status_code >= 400:
        raise HTTPException(status_code=502, detail="Vault backend returned an error.")
    payload = response.json()
    data = payload.get("data", {}).get("data", {})
    if not isinstance(data, dict):
        raise HTTPException(status_code=502, detail="Vault backend returned an invalid KV payload.")
    return data


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


class PlatformSecretStatusResponse(BaseModel):
    ok: bool
    path: str
    present: list[str]
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
        "platformSecretSource": {
            "enabled": bool(os.getenv("VAULT_ADDR")),
            "mount": os.getenv("VAULT_KV_MOUNT", "k3s-kv"),
            "path": os.getenv("VAULT_PLATFORM_SECRET_PATH", "platform"),
            "auth": "kubernetes",
            "role": os.getenv("VAULT_K8S_ROLE", "dev-infra-broker-platform-reader"),
            "keys": PLATFORM_SECRET_KEYS,
            "returnsSecretValues": False,
        },
        "rules": [
            "Broker clients never receive Vault paths or Vault tokens.",
            "Broker responses never include secret values.",
            "Write-capable endpoints require authn, authz, and audit before enablement.",
        ],
    }


@app.get(
    "/v1/platform/secrets/status",
    response_model=PlatformSecretStatusResponse,
    tags=["platform-secrets"],
)
def platform_secret_status() -> PlatformSecretStatusResponse:
    _, mount, path = _vault_settings()
    data = _read_vault_kv2_secret(mount, path)
    present = [key for key in PLATFORM_SECRET_KEYS if key in data and data[key] not in (None, "")]
    missing = [key for key in PLATFORM_SECRET_KEYS if key not in present]
    return PlatformSecretStatusResponse(
        ok=not missing,
        path=f"{mount}/{path}",
        present=present,
        missing=missing,
    )


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
