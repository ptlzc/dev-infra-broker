import base64
from enum import StrEnum
import os
import secrets
import string
from typing import Annotated

import httpx
from fastapi import FastAPI, HTTPException, Path
from nacl import encoding, public
from pydantic import BaseModel, Field


app = FastAPI(
    title="Dev Infra Broker",
    version="0.1.0",
    description=(
        "Internal broker for k3s deployment automation. "
        "Secret values remain internal and are never returned to callers."
    ),
)

PLATFORM_SECRET_KEYS = [
    "REGISTRY_USERNAME",
    "REGISTRY_PASSWORD",
    "REGISTRY_URL",
    "REGISTRY_NAMESPACE",
    "GH_PAT",
]

GITHUB_ACTIONS_SYNC_KEYS = [
    "REGISTRY_USERNAME",
    "REGISTRY_PASSWORD",
    "REGISTRY_URL",
    "REGISTRY_NAMESPACE",
]

SECRET_KEY_ALPHABET = string.ascii_letters + string.digits + "-_"


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


def _patch_vault_kv2_secret(mount: str, path: str, values: dict[str, str]) -> None:
    if not values:
        return
    address, _, _ = _vault_settings()
    token = _vault_token()
    url = f"{address}/v1/{mount}/data/{path}"
    try:
        response = httpx.patch(
            url,
            headers={
                "X-Vault-Token": token,
                "Content-Type": "application/merge-patch+json",
            },
            json={"data": values},
            timeout=5.0,
        )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="Vault backend patch failed.") from exc
    if response.status_code in {401, 403}:
        raise HTTPException(status_code=503, detail="Vault backend write access is denied.")
    if response.status_code >= 400:
        raise HTTPException(status_code=502, detail="Vault backend write returned an error.")


def _platform_secret_source() -> dict[str, object]:
    _, mount, path = _vault_settings()
    data = _read_vault_kv2_secret(mount, path)
    missing = [key for key in PLATFORM_SECRET_KEYS if key not in data or data[key] in (None, "")]
    if missing:
        raise HTTPException(
            status_code=503,
            detail={"message": "Platform secret source is incomplete.", "missing": missing},
        )
    return data


def _require_platform_value(source: dict[str, object], key: str) -> str:
    value = source.get(key)
    if not isinstance(value, str) or not value:
        raise HTTPException(status_code=503, detail=f"Platform secret key {key} is missing.")
    return value


def _generate_secret(spec: "GeneratedSecretSpec") -> str:
    if spec.generator == Generator.RANDOM_BASE64:
        size = spec.bytes or 32
        return base64.b64encode(secrets.token_bytes(size)).decode("ascii")
    if spec.generator == Generator.RANDOM_HEX:
        size = spec.bytes or 32
        return secrets.token_hex(size)
    if spec.generator == Generator.RANDOM_PASSWORD:
        length = spec.length or 32
        return "".join(secrets.choice(SECRET_KEY_ALPHABET) for _ in range(length))
    raise HTTPException(status_code=400, detail="Unsupported generator.")


def _encrypt_github_secret(public_key: str, value: str) -> str:
    key = public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder())
    sealed_box = public.SealedBox(key)
    encrypted = sealed_box.encrypt(value.encode("utf-8"))
    return base64.b64encode(encrypted).decode("ascii")


def _github_request(
    method: str,
    url: str,
    token: str,
    *,
    json_body: dict[str, object] | None = None,
) -> httpx.Response:
    try:
        return httpx.request(
            method,
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            json=json_body,
            timeout=10.0,
        )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="GitHub API request failed.") from exc


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
        "mode": "vault-backed-writes-enabled",
        "runtimeSecretSets": {
            "enabled": True,
            "generators": [item.value for item in Generator],
            "returnsSecretValues": False,
        },
        "githubActionsSecrets": {
            "enabled": True,
            "allowedKeys": GITHUB_ACTIONS_SYNC_KEYS,
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
            "GitHub Actions secret sync never exports GH_PAT to target repositories.",
            "Runtime generated secrets are generated only when absent to avoid unintended rotation.",
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
    request = _
    _, mount, _ = _vault_settings()
    path = f"projects/{request.namespace}/{request.serviceAccountName}/env"
    existing = _read_vault_kv2_secret(mount, path)

    generated_written: list[str] = []
    generated_values: dict[str, str] = {}
    for key, spec in request.generated.items():
        if not key.replace("_", "").isalnum() or not key or key[0].isdigit():
            raise HTTPException(status_code=400, detail=f"Invalid generated secret key: {key}")
        if key in existing and existing[key] not in (None, ""):
            continue
        generated_values[key] = _generate_secret(spec)
        generated_written.append(key)

    _patch_vault_kv2_secret(mount, path, generated_values)

    after = {**existing, **generated_values}
    required_present = [
        key for key in request.requiredExisting if key in after and after[key] not in (None, "")
    ]
    required_missing = [key for key in request.requiredExisting if key not in required_present]

    return RuntimeSecretEnsureResponse(
        ok=not required_missing,
        destinationSecretName=request.destinationSecretName,
        generatedWritten=generated_written,
        requiredExistingPresent=required_present,
        requiredExistingMissing=required_missing,
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
    request = _
    requested = list(dict.fromkeys(request.keys))
    unsupported = [key for key in requested if key not in GITHUB_ACTIONS_SYNC_KEYS]
    if unsupported:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Unsupported GitHub Actions secret keys.",
                "unsupported": unsupported,
                "allowed": GITHUB_ACTIONS_SYNC_KEYS,
            },
        )

    source = _platform_secret_source()
    missing = [key for key in requested if key not in source or source[key] in (None, "")]
    if missing:
        return GitHubActionsSecretSyncResponse(
            ok=False,
            repository=f"{owner}/{repo}",
            synced=[],
            missing=missing,
        )

    github_token = _require_platform_value(source, "GH_PAT")
    public_key_response = _github_request(
        "GET",
        f"https://api.github.com/repos/{owner}/{repo}/actions/secrets/public-key",
        github_token,
    )
    if public_key_response.status_code == 404:
        raise HTTPException(status_code=404, detail="GitHub repository was not found or is inaccessible.")
    if public_key_response.status_code in {401, 403}:
        raise HTTPException(status_code=503, detail="GitHub token cannot manage repository secrets.")
    if public_key_response.status_code >= 400:
        raise HTTPException(status_code=502, detail="GitHub public key request failed.")

    key_payload = public_key_response.json()
    public_key = key_payload.get("key")
    key_id = key_payload.get("key_id")
    if not isinstance(public_key, str) or not isinstance(key_id, str):
        raise HTTPException(status_code=502, detail="GitHub public key response was invalid.")

    synced: list[str] = []
    for key in requested:
        value = _require_platform_value(source, key)
        encrypted_value = _encrypt_github_secret(public_key, value)
        put_response = _github_request(
            "PUT",
            f"https://api.github.com/repos/{owner}/{repo}/actions/secrets/{key}",
            github_token,
            json_body={"encrypted_value": encrypted_value, "key_id": key_id},
        )
        if put_response.status_code not in {201, 204}:
            if put_response.status_code in {401, 403}:
                raise HTTPException(status_code=503, detail="GitHub token cannot write repository secrets.")
            raise HTTPException(status_code=502, detail=f"GitHub secret sync failed for {key}.")
        synced.append(key)

    return GitHubActionsSecretSyncResponse(
        ok=True,
        repository=f"{owner}/{repo}",
        synced=synced,
        missing=[],
    )
