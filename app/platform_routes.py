from __future__ import annotations

from fastapi import APIRouter, HTTPException, Path

from .platform_services import (
    GITHUB_ACTIONS_SYNC_KEYS,
    PLATFORM_SECRET_KEYS,
    GitHubActionsSecretSyncRequest,
    GitHubActionsSecretSyncResponse,
    PlatformSecretStatusResponse,
    RuntimeSecretEnsureRequest,
    RuntimeSecretEnsureResponse,
    _encrypt_github_secret,
    _generate_secret,
    _github_request,
    _patch_vault_kv2_secret,
    _platform_secret_source,
    _read_vault_kv2_secret,
    _require_platform_value,
    _vault_settings,
)


router = APIRouter()


@router.get(
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


@router.post(
    "/v1/runtime-secret-sets/ensure",
    response_model=RuntimeSecretEnsureResponse,
    tags=["runtime-secrets"],
)
def ensure_runtime_secret_set(request: RuntimeSecretEnsureRequest) -> RuntimeSecretEnsureResponse:
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
    required_present = [key for key in request.requiredExisting if key in after and after[key] not in (None, "")]
    required_missing = [key for key in request.requiredExisting if key not in required_present]

    return RuntimeSecretEnsureResponse(
        ok=not required_missing,
        destinationSecretName=request.destinationSecretName,
        generatedWritten=generated_written,
        requiredExistingPresent=required_present,
        requiredExistingMissing=required_missing,
    )


@router.post(
    "/v1/github/repositories/{owner}/{repo}/actions-secrets/sync",
    response_model=GitHubActionsSecretSyncResponse,
    tags=["github"],
)
def sync_github_actions_secrets(
    owner: str = Path(pattern=r"^[A-Za-z0-9_.-]+$"),
    repo: str = Path(pattern=r"^[A-Za-z0-9_.-]+$"),
    request: GitHubActionsSecretSyncRequest = ...,
) -> GitHubActionsSecretSyncResponse:
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
