from __future__ import annotations

import os

import httpx
from fastapi import HTTPException


def _kubernetes_settings() -> tuple[str, str, str]:
    host = os.getenv("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc").strip()
    port = os.getenv("KUBERNETES_SERVICE_PORT", "443").strip()
    token_path = os.getenv(
        "KUBERNETES_SERVICE_ACCOUNT_TOKEN_PATH",
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
    )
    ca_path = os.getenv(
        "KUBERNETES_SERVICE_ACCOUNT_CA_PATH",
        "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
    )
    if not host or not port:
        raise HTTPException(status_code=503, detail="Kubernetes backend is not configured for dev-infra-broker.")
    return f"https://{host}:{port}", token_path, ca_path


def _kubernetes_token(token_path: str) -> str:
    try:
        with open(token_path, encoding="utf-8") as token_file:
            token = token_file.read().strip()
    except OSError as exc:
        raise HTTPException(status_code=503, detail="Kubernetes service account token is unavailable.") from exc
    if not token:
        raise HTTPException(status_code=503, detail="Kubernetes service account token is empty.")
    return token


def _kubernetes_request(method: str, path: str, *, params: dict[str, object] | None = None) -> httpx.Response:
    base_url, token_path, ca_path = _kubernetes_settings()
    try:
        return httpx.request(
            method,
            f"{base_url}{path}",
            headers={"Authorization": f"Bearer {_kubernetes_token(token_path)}"},
            params=params,
            verify=ca_path,
            timeout=10.0,
        )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="Kubernetes API request failed.") from exc


def _response_error_body(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return response.text[:500]
    message = payload.get("message") if isinstance(payload, dict) else None
    if isinstance(message, str):
        return message[:500]
    return response.text[:500]


def _raise_kubernetes_response_error(response: httpx.Response, action: str) -> None:
    if response.status_code == 404:
        raise HTTPException(
            status_code=404,
            detail={
                "message": f"Kubernetes resource was not found while {action}.",
                "backendStatusCode": response.status_code,
                "backendMessage": _response_error_body(response),
            },
        )
    if response.status_code in {401, 403}:
        raise HTTPException(
            status_code=403,
            detail={
                "message": f"Kubernetes API access was denied while {action}.",
                "backendStatusCode": response.status_code,
                "backendMessage": _response_error_body(response),
            },
        )
    if response.status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail={
                "message": f"Kubernetes API returned an error while {action}.",
                "backendStatusCode": response.status_code,
                "backendMessage": _response_error_body(response),
            },
        )


def _kubernetes_json_request(method: str, path: str, *, params: dict[str, object] | None = None, action: str) -> dict[str, object]:
    response = _kubernetes_request(method, path, params=params)
    _raise_kubernetes_response_error(response, action)
    try:
        payload = response.json()
    except ValueError as exc:
        raise HTTPException(status_code=502, detail={"message": f"Kubernetes API returned invalid JSON while {action}."}) from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=502, detail={"message": f"Kubernetes API returned an invalid payload while {action}."})
    return payload
