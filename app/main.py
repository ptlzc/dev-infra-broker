import base64
import glob
from enum import StrEnum
import os
import re
import secrets
import string
from typing import Annotated, Any

import httpx
from fastapi import FastAPI, HTTPException, Path, Query
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
LOG_QUERY_DENIED_NAMESPACE_PREFIXES = tuple(
    prefix.strip()
    for prefix in os.getenv(
        "LOG_QUERY_DENIED_NAMESPACE_PREFIXES",
        "kube-,argocd,edge-system,cert-manager,traefik-,vault-secrets-operator-system,default,platform-app-deploy",
    ).split(",")
    if prefix.strip()
)
LOG_QUERY_DEFAULT_TAIL_LINES = int(os.getenv("LOG_QUERY_DEFAULT_TAIL_LINES", "200"))
LOG_QUERY_MAX_TAIL_LINES = int(os.getenv("LOG_QUERY_MAX_TAIL_LINES", "2000"))
LOG_QUERY_DEFAULT_LIMIT_BYTES = int(os.getenv("LOG_QUERY_DEFAULT_LIMIT_BYTES", "262144"))
LOG_QUERY_MAX_LIMIT_BYTES = int(os.getenv("LOG_QUERY_MAX_LIMIT_BYTES", "1048576"))
ARGOCD_APPLICATION_NAMESPACE = os.getenv("ARGOCD_APPLICATION_NAMESPACE", "argocd")
LOG_REDACTION_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"(?is)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----"),
        "[REDACTED_PRIVATE_KEY_BLOCK]",
    ),
    (
        re.compile(r"(?i)\b(authorization\s*:\s*bearer\s+)[^\s]+"),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*([^\s'\"`]+)"),
        r"\1=[REDACTED]",
    ),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]+\b"), "[REDACTED_SLACK_TOKEN]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_ACCESS_KEY]"),
)


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
    if response.status_code in {404, 405}:
        try:
            response = httpx.post(
                url,
                headers={"X-Vault-Token": token},
                json={"data": values},
                timeout=5.0,
            )
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="Vault backend create failed.") from exc
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


def _namespace_allowed_for_log_query(namespace: str) -> bool:
    return not any(namespace == prefix or namespace.startswith(prefix) for prefix in LOG_QUERY_DENIED_NAMESPACE_PREFIXES)


def _require_namespace_allowed_for_kubernetes_query(namespace: str) -> None:
    if not _namespace_allowed_for_log_query(namespace):
        raise HTTPException(
            status_code=403,
            detail={
                "message": "Kubernetes queries are limited to non-system application namespaces.",
                "namespace": namespace,
            },
        )


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


def _kubernetes_json_request(method: str, path: str, *, params: dict[str, object] | None = None, action: str) -> dict[str, Any]:
    response = _kubernetes_request(method, path, params=params)
    _raise_kubernetes_response_error(response, action)
    try:
        payload = response.json()
    except ValueError as exc:
        raise HTTPException(
            status_code=502,
            detail={"message": f"Kubernetes API returned invalid JSON while {action}."},
        ) from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=502, detail={"message": f"Kubernetes API returned an invalid payload while {action}."})
    return payload


def _redact_log_text(text: str) -> tuple[str, bool]:
    redacted = False
    for pattern, replacement in LOG_REDACTION_RULES:
        text, count = pattern.subn(replacement, text)
        redacted = redacted or count > 0
    return text, redacted


def _log_query_params(
    *,
    container: str | None,
    previous: bool,
    tailLines: int | None,
    sinceSeconds: int | None,
    limitBytes: int | None,
    timestamps: bool,
) -> dict[str, object]:
    params: dict[str, object] = {
        "previous": str(previous).lower(),
        "timestamps": str(timestamps).lower(),
    }
    if container:
        params["container"] = container
    if tailLines is not None:
        params["tailLines"] = tailLines
    if sinceSeconds is not None:
        params["sinceSeconds"] = sinceSeconds
    if limitBytes is not None:
        params["limitBytes"] = limitBytes
    return params


def _rotation_index(path: str) -> int:
    name = os.path.basename(path)
    number = name.split(".", 1)[0]
    try:
        return int(number)
    except ValueError:
        return 0


def _local_pod_log_files(namespace: str, pod: str, container: str | None, previous: bool) -> list[str]:
    root = os.getenv("LOG_QUERY_LOCAL_ROOT", "/host/var/log/pods").rstrip("/")
    pod_dirs = [path for path in glob.glob(os.path.join(root, f"{namespace}_{pod}_*")) if os.path.isdir(path)]
    if not pod_dirs:
        return []

    pod_dir = max(pod_dirs, key=os.path.getmtime)
    if container:
        container_dirs = [os.path.join(pod_dir, container)] if os.path.isdir(os.path.join(pod_dir, container)) else []
    else:
        container_dirs = [path for path in glob.glob(os.path.join(pod_dir, "*")) if os.path.isdir(path)]
        if len(container_dirs) > 1:
            raise HTTPException(
                status_code=400,
                detail="Container is required when the pod has more than one container.",
            )

    files: list[str] = []
    for container_dir in container_dirs:
        logs = [path for path in glob.glob(os.path.join(container_dir, "*.log")) if os.path.isfile(path)]
        if previous:
            logs = [path for path in logs if _rotation_index(path) > 0] or logs
        else:
            logs = [path for path in logs if _rotation_index(path) == 0] or logs
        files.extend(sorted(logs, key=_rotation_index, reverse=previous))
    return files


def _read_local_pod_logs(namespace: str, pod: str, container: str | None, previous: bool) -> str:
    files = _local_pod_log_files(namespace, pod, container, previous)
    if not files:
        raise FileNotFoundError

    chunks: list[str] = []
    for path in sorted(files, key=lambda item: (_rotation_index(item), item)):
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                content = handle.read()
        except OSError as exc:
            raise HTTPException(status_code=502, detail="Local pod log read failed.") from exc
        if content:
            chunks.append(content.rstrip("\n"))
    return "\n".join(chunks)


def _finalize_log_text(
    text: str,
    *,
    tail_lines: int | None,
    limit_bytes: int | None,
) -> tuple[str, bool, bool]:
    redacted_text, redacted = _redact_log_text(text)
    truncated = False

    if tail_lines is not None:
        lines = redacted_text.splitlines(keepends=True)
        if len(lines) > tail_lines:
            redacted_text = "".join(lines[-tail_lines:])
            truncated = True

    if limit_bytes is not None:
        encoded = redacted_text.encode("utf-8")
        if len(encoded) > limit_bytes:
            redacted_text = encoded[:limit_bytes].decode("utf-8", errors="ignore")
            truncated = True

    return redacted_text, redacted, truncated


def _read_kubernetes_pod_logs(
    namespace: str,
    pod: str,
    container: str | None,
    previous: bool,
    tail_lines: int | None,
    since_seconds: int | None,
    limit_bytes: int | None,
    timestamps: bool,
) -> str:
    params = _log_query_params(
        container=container,
        previous=previous,
        tailLines=tail_lines,
        sinceSeconds=since_seconds,
        limitBytes=limit_bytes,
        timestamps=timestamps,
    )
    response = _kubernetes_request("GET", f"/api/v1/namespaces/{namespace}/pods/{pod}/log", params=params)
    _raise_kubernetes_response_error(response, "querying pod logs")
    return response.text


def _restart_count(container_statuses: list[dict[str, Any]]) -> int:
    return sum(status.get("restartCount", 0) for status in container_statuses if isinstance(status.get("restartCount", 0), int))


def _list_or_empty(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _dict_or_empty(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _container_status_summary(status: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": status.get("name"),
        "ready": status.get("ready"),
        "restartCount": status.get("restartCount"),
        "state": status.get("state"),
        "lastState": status.get("lastState"),
        "image": status.get("image"),
        "started": status.get("started"),
    }


def _pod_summary(item: dict[str, Any]) -> dict[str, Any]:
    metadata = _dict_or_empty(item.get("metadata"))
    status = _dict_or_empty(item.get("status"))
    spec = _dict_or_empty(item.get("spec"))
    container_statuses = _list_or_empty(status.get("containerStatuses"))
    init_container_statuses = _list_or_empty(status.get("initContainerStatuses"))
    normalized_statuses = [status for status in container_statuses if isinstance(status, dict)]
    normalized_init_statuses = [status for status in init_container_statuses if isinstance(status, dict)]
    return {
        "podName": metadata.get("name"),
        "phase": status.get("phase"),
        "restartCount": _restart_count(normalized_statuses + normalized_init_statuses),
        "nodeName": spec.get("nodeName"),
        "ownerReferences": _list_or_empty(metadata.get("ownerReferences")),
        "containerStatuses": [_container_status_summary(status) for status in normalized_statuses],
        "initContainerStatuses": [_container_status_summary(status) for status in normalized_init_statuses],
        "creationTimestamp": metadata.get("creationTimestamp"),
        "startTime": status.get("startTime"),
        "labels": _dict_or_empty(metadata.get("labels")),
    }


def _list_pods_payload(
    namespace: str,
    *,
    label_selector: str | None,
    field_selector: str | None,
    phase: str | None,
) -> tuple[list[dict[str, Any]], str | None]:
    field_parts = [part for part in [field_selector, f"status.phase={phase}" if phase else None] if part]
    params: dict[str, object] = {}
    if label_selector:
        params["labelSelector"] = label_selector
    if field_parts:
        params["fieldSelector"] = ",".join(field_parts)
    payload = _kubernetes_json_request(
        "GET",
        f"/api/v1/namespaces/{namespace}/pods",
        params=params,
        action="listing pods",
    )
    items = payload.get("items", [])
    if not isinstance(items, list):
        raise HTTPException(status_code=502, detail={"message": "Kubernetes pod list response was invalid."})
    pods = [item for item in items if isinstance(item, dict)]
    if phase:
        pods = [pod for pod in pods if pod.get("status", {}).get("phase") == phase]
    return pods, params.get("fieldSelector") if isinstance(params.get("fieldSelector"), str) else None


def _label_selector_from_workload_selector(selector: dict[str, Any]) -> str:
    parts: list[str] = []
    match_labels = selector.get("matchLabels", {})
    if isinstance(match_labels, dict):
        parts.extend(f"{key}={value}" for key, value in sorted(match_labels.items()))

    match_expressions = selector.get("matchExpressions", [])
    if isinstance(match_expressions, list):
        for expression in match_expressions:
            if not isinstance(expression, dict):
                continue
            key = expression.get("key")
            operator = expression.get("operator")
            values = expression.get("values", [])
            if not isinstance(key, str) or not isinstance(operator, str):
                continue
            if operator == "In" and isinstance(values, list):
                parts.append(f"{key} in ({','.join(str(value) for value in values)})")
            elif operator == "NotIn" and isinstance(values, list):
                parts.append(f"{key} notin ({','.join(str(value) for value in values)})")
            elif operator == "Exists":
                parts.append(key)
            elif operator == "DoesNotExist":
                parts.append(f"!{key}")

    if not parts:
        raise HTTPException(status_code=502, detail={"message": "Workload selector is empty or unsupported."})
    return ",".join(parts)


def _workload_payload(namespace: str, kind: str, name: str) -> dict[str, Any]:
    resource = "deployments" if kind == "Deployment" else "statefulsets"
    return _kubernetes_json_request(
        "GET",
        f"/apis/apps/v1/namespaces/{namespace}/{resource}/{name}",
        action=f"reading {kind.lower()} status",
    )


def _pods_for_workload(namespace: str, kind: str, name: str) -> tuple[list[dict[str, Any]], str]:
    workload = _workload_payload(namespace, kind, name)
    spec = _dict_or_empty(workload.get("spec"))
    selector = _dict_or_empty(spec.get("selector"))
    label_selector = _label_selector_from_workload_selector(selector)
    pods, _ = _list_pods_payload(namespace, label_selector=label_selector, field_selector=None, phase=None)
    return pods, label_selector


def _pod_sort_key(pod: dict[str, Any]) -> tuple[str, str]:
    metadata = _dict_or_empty(pod.get("metadata"))
    status = _dict_or_empty(pod.get("status"))
    timestamp = metadata.get("creationTimestamp") or status.get("startTime") or ""
    name = metadata.get("name") or ""
    return str(timestamp), str(name)


def _select_latest_pod(pods: list[dict[str, Any]]) -> dict[str, Any]:
    if not pods:
        raise HTTPException(status_code=404, detail={"message": "No pods matched the requested selector."})
    return max(pods, key=_pod_sort_key)


def _event_summary(event: dict[str, Any]) -> dict[str, Any]:
    metadata = _dict_or_empty(event.get("metadata"))
    return {
        "name": metadata.get("name"),
        "type": event.get("type"),
        "reason": event.get("reason"),
        "message": event.get("message"),
        "count": event.get("count"),
        "firstTimestamp": event.get("firstTimestamp"),
        "lastTimestamp": event.get("lastTimestamp"),
        "eventTime": event.get("eventTime"),
        "involvedObject": _dict_or_empty(event.get("involvedObject")),
    }


def _list_events_payload(
    namespace: str,
    *,
    involved_object_kind: str | None,
    involved_object_name: str | None,
    involved_object_uid: str | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    field_parts = []
    if involved_object_kind:
        field_parts.append(f"involvedObject.kind={involved_object_kind}")
    if involved_object_name:
        field_parts.append(f"involvedObject.name={involved_object_name}")
    if involved_object_uid:
        field_parts.append(f"involvedObject.uid={involved_object_uid}")
    params: dict[str, object] = {}
    if field_parts:
        params["fieldSelector"] = ",".join(field_parts)
    payload = _kubernetes_json_request(
        "GET",
        f"/api/v1/namespaces/{namespace}/events",
        params=params,
        action="listing events",
    )
    items = payload.get("items", [])
    if not isinstance(items, list):
        raise HTTPException(status_code=502, detail={"message": "Kubernetes event list response was invalid."})
    return [item for item in items if isinstance(item, dict)], params.get("fieldSelector") if isinstance(params.get("fieldSelector"), str) else None


def _workload_status_summary(namespace: str, kind: str, name: str) -> dict[str, Any]:
    payload = _workload_payload(namespace, kind, name)
    spec = _dict_or_empty(payload.get("spec"))
    status = _dict_or_empty(payload.get("status"))
    events, _ = _list_events_payload(
        namespace,
        involved_object_kind=kind,
        involved_object_name=name,
    )
    return {
        "ok": True,
        "namespace": namespace,
        "kind": kind,
        "name": name,
        "desiredReplicas": spec.get("replicas", 1),
        "readyReplicas": status.get("readyReplicas", 0),
        "availableReplicas": status.get("availableReplicas", 0),
        "updatedReplicas": status.get("updatedReplicas", 0),
        "currentReplicas": status.get("currentReplicas"),
        "observedGeneration": status.get("observedGeneration"),
        "conditions": [condition for condition in _list_or_empty(status.get("conditions")) if isinstance(condition, dict)],
        "events": [_event_summary(event) for event in events],
    }


def _build_pod_logs_response(
    namespace: str,
    pod: str,
    *,
    selection: dict[str, Any] | None,
    container: str | None,
    previous: bool,
    tail_lines: int | None,
    since_seconds: int | None,
    limit_bytes: int | None,
    timestamps: bool,
) -> "PodLogsResponse":
    source = "kubernetes-api"
    try:
        logs = _read_kubernetes_pod_logs(
            namespace,
            pod,
            container,
            previous,
            tail_lines,
            since_seconds,
            limit_bytes,
            timestamps,
        )
    except HTTPException as kubernetes_error:
        try:
            logs = _read_local_pod_logs(namespace, pod, container, previous)
            source = "local-node-log-file"
        except FileNotFoundError:
            raise kubernetes_error

    logs, redacted, truncated = _finalize_log_text(logs, tail_lines=tail_lines, limit_bytes=limit_bytes)
    return PodLogsResponse(
        ok=True,
        source=source,
        namespace=namespace,
        pod=pod,
        resolvedPodName=pod,
        selection=selection,
        container=container,
        previous=previous,
        tailLines=tail_lines,
        sinceSeconds=since_seconds,
        limitBytes=limit_bytes,
        timestamps=timestamps,
        redacted=redacted,
        truncated=truncated,
        logs=logs,
    )


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


class PodSummary(BaseModel):
    podName: str | None
    phase: str | None
    restartCount: int
    nodeName: str | None
    ownerReferences: list[dict[str, Any]]
    containerStatuses: list[dict[str, Any]]
    initContainerStatuses: list[dict[str, Any]]
    creationTimestamp: str | None
    startTime: str | None
    labels: dict[str, Any]


class PodListResponse(BaseModel):
    ok: bool
    namespace: str
    labelSelector: str | None
    fieldSelector: str | None
    phase: str | None
    count: int
    pods: list[PodSummary]


class KubernetesEventSummary(BaseModel):
    name: str | None
    type: str | None
    reason: str | None
    message: str | None
    count: int | None
    firstTimestamp: str | None
    lastTimestamp: str | None
    eventTime: str | None
    involvedObject: dict[str, Any]


class EventListResponse(BaseModel):
    ok: bool
    namespace: str
    fieldSelector: str | None
    count: int
    events: list[KubernetesEventSummary]


class WorkloadStatusResponse(BaseModel):
    ok: bool
    namespace: str
    kind: str
    name: str
    desiredReplicas: int | None
    readyReplicas: int | None
    availableReplicas: int | None
    updatedReplicas: int | None
    currentReplicas: int | None = None
    observedGeneration: int | None
    conditions: list[dict[str, Any]]
    events: list[KubernetesEventSummary]


class PodLogsResponse(BaseModel):
    ok: bool
    source: str
    namespace: str
    pod: str
    resolvedPodName: str
    selection: dict[str, Any] | None = None
    container: str | None
    previous: bool
    tailLines: int | None
    sinceSeconds: int | None
    limitBytes: int | None
    timestamps: bool
    redacted: bool
    truncated: bool
    logs: str


class ArgoCDApplicationResponse(BaseModel):
    ok: bool
    name: str
    namespace: str
    sync: dict[str, Any]
    health: dict[str, Any]
    operationState: dict[str, Any] | None
    revision: str | None


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
        "podLogs": {
            "enabled": True,
            "endpointPatterns": [
                "GET /v1/kubernetes/namespaces/<namespace>/pods/<pod>/logs",
                "GET /v1/kubernetes/namespaces/<namespace>/deployments/<name>/logs",
                "GET /v1/kubernetes/namespaces/<namespace>/pods/logs?labelSelector=<selector>",
            ],
            "namespacePolicy": {
                "mode": "non-system-namespaces-only",
                "deniedPrefixes": list(LOG_QUERY_DENIED_NAMESPACE_PREFIXES),
            },
            "limits": {
                "defaultTailLines": LOG_QUERY_DEFAULT_TAIL_LINES,
                "maxTailLines": LOG_QUERY_MAX_TAIL_LINES,
                "defaultLimitBytes": LOG_QUERY_DEFAULT_LIMIT_BYTES,
                "maxLimitBytes": LOG_QUERY_MAX_LIMIT_BYTES,
                "follow": False,
            },
            "redaction": {
                "enabled": True,
                "mode": "best-effort-pattern-redaction",
            },
            "selection": {
                "latestPodBy": "metadata.creationTimestamp",
                "returnsResolvedPodName": True,
            },
        },
        "kubernetesDiscovery": {
            "enabled": True,
            "endpoints": [
                "GET /v1/kubernetes/namespaces/<namespace>/pods",
                "GET /v1/kubernetes/namespaces/<namespace>/deployments/<name>",
                "GET /v1/kubernetes/namespaces/<namespace>/statefulsets/<name>",
                "GET /v1/kubernetes/namespaces/<namespace>/deployments/<name>/pods",
                "GET /v1/kubernetes/namespaces/<namespace>/events",
            ],
            "namespacePolicy": {
                "mode": "non-system-namespaces-only",
                "deniedPrefixes": list(LOG_QUERY_DENIED_NAMESPACE_PREFIXES),
            },
        },
        "argocdApplications": {
            "enabled": True,
            "endpointPattern": "GET /v1/argocd/applications/<name>",
            "namespace": ARGOCD_APPLICATION_NAMESPACE,
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


@app.get(
    "/v1/kubernetes/namespaces/{namespace}/pods",
    response_model=PodListResponse,
    tags=["kubernetes", "discovery"],
)
def list_pods(
    namespace: Annotated[str, Path(pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")],
    labelSelector: str | None = Query(default=None, min_length=1, max_length=512),
    fieldSelector: str | None = Query(default=None, min_length=1, max_length=512),
    phase: str | None = Query(default=None, pattern=r"^(Pending|Running|Succeeded|Failed|Unknown)$"),
) -> PodListResponse:
    _require_namespace_allowed_for_kubernetes_query(namespace)
    pods, resolved_field_selector = _list_pods_payload(
        namespace,
        label_selector=labelSelector,
        field_selector=fieldSelector,
        phase=phase,
    )
    summaries = [_pod_summary(pod) for pod in pods]
    return PodListResponse(
        ok=True,
        namespace=namespace,
        labelSelector=labelSelector,
        fieldSelector=resolved_field_selector,
        phase=phase,
        count=len(summaries),
        pods=summaries,
    )


@app.get(
    "/v1/kubernetes/namespaces/{namespace}/deployments/{name}",
    response_model=WorkloadStatusResponse,
    tags=["kubernetes", "workloads"],
)
def get_deployment_status(
    namespace: Annotated[str, Path(pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")],
    name: Annotated[str, Path(pattern=r"^[a-z0-9]([-.a-z0-9]*[a-z0-9])?$")],
) -> WorkloadStatusResponse:
    _require_namespace_allowed_for_kubernetes_query(namespace)
    return WorkloadStatusResponse(**_workload_status_summary(namespace, "Deployment", name))


@app.get(
    "/v1/kubernetes/namespaces/{namespace}/statefulsets/{name}",
    response_model=WorkloadStatusResponse,
    tags=["kubernetes", "workloads"],
)
def get_statefulset_status(
    namespace: Annotated[str, Path(pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")],
    name: Annotated[str, Path(pattern=r"^[a-z0-9]([-.a-z0-9]*[a-z0-9])?$")],
) -> WorkloadStatusResponse:
    _require_namespace_allowed_for_kubernetes_query(namespace)
    return WorkloadStatusResponse(**_workload_status_summary(namespace, "StatefulSet", name))


@app.get(
    "/v1/kubernetes/namespaces/{namespace}/deployments/{name}/pods",
    response_model=PodListResponse,
    tags=["kubernetes", "discovery"],
)
def list_deployment_pods(
    namespace: Annotated[str, Path(pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")],
    name: Annotated[str, Path(pattern=r"^[a-z0-9]([-.a-z0-9]*[a-z0-9])?$")],
    phase: str | None = Query(default=None, pattern=r"^(Pending|Running|Succeeded|Failed|Unknown)$"),
) -> PodListResponse:
    _require_namespace_allowed_for_kubernetes_query(namespace)
    pods, label_selector = _pods_for_workload(namespace, "Deployment", name)
    if phase:
        pods = [pod for pod in pods if _dict_or_empty(pod.get("status")).get("phase") == phase]
    summaries = [_pod_summary(pod) for pod in pods]
    return PodListResponse(
        ok=True,
        namespace=namespace,
        labelSelector=label_selector,
        fieldSelector=f"status.phase={phase}" if phase else None,
        phase=phase,
        count=len(summaries),
        pods=summaries,
    )


@app.get(
    "/v1/kubernetes/namespaces/{namespace}/events",
    response_model=EventListResponse,
    tags=["kubernetes", "events"],
)
def list_events(
    namespace: Annotated[str, Path(pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")],
    involvedObjectKind: str | None = Query(default=None, pattern=r"^[A-Za-z][A-Za-z0-9]*$"),
    involvedObjectName: str | None = Query(default=None, pattern=r"^[A-Za-z0-9]([-.A-Za-z0-9]*[A-Za-z0-9])?$"),
    involvedObjectUid: str | None = Query(default=None, min_length=1, max_length=128),
) -> EventListResponse:
    _require_namespace_allowed_for_kubernetes_query(namespace)
    events, field_selector = _list_events_payload(
        namespace,
        involved_object_kind=involvedObjectKind,
        involved_object_name=involvedObjectName,
        involved_object_uid=involvedObjectUid,
    )
    summaries = [_event_summary(event) for event in events]
    return EventListResponse(
        ok=True,
        namespace=namespace,
        fieldSelector=field_selector,
        count=len(summaries),
        events=summaries,
    )


@app.get(
    "/v1/kubernetes/namespaces/{namespace}/pods/logs",
    response_model=PodLogsResponse,
    tags=["kubernetes", "logs"],
)
def get_latest_pod_logs_by_selector(
    namespace: Annotated[str, Path(pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")],
    labelSelector: str = Query(min_length=1, max_length=512),
    phase: str | None = Query(default=None, pattern=r"^(Pending|Running|Succeeded|Failed|Unknown)$"),
    container: str | None = Query(default=None, pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"),
    previous: bool = Query(default=False),
    tailLines: int | None = Query(default=LOG_QUERY_DEFAULT_TAIL_LINES, ge=1, le=LOG_QUERY_MAX_TAIL_LINES),
    sinceSeconds: int | None = Query(default=None, ge=1, le=86400),
    limitBytes: int | None = Query(default=LOG_QUERY_DEFAULT_LIMIT_BYTES, ge=1, le=LOG_QUERY_MAX_LIMIT_BYTES),
    timestamps: bool = Query(default=False),
) -> PodLogsResponse:
    _require_namespace_allowed_for_kubernetes_query(namespace)
    pods, field_selector = _list_pods_payload(
        namespace,
        label_selector=labelSelector,
        field_selector=None,
        phase=phase,
    )
    pod = _select_latest_pod(pods)
    pod_name = _dict_or_empty(pod.get("metadata")).get("name")
    if not isinstance(pod_name, str):
        raise HTTPException(status_code=502, detail={"message": "Selected pod did not include a name."})
    return _build_pod_logs_response(
        namespace,
        pod_name,
        selection={
            "mode": "labelSelector",
            "labelSelector": labelSelector,
            "fieldSelector": field_selector,
            "phase": phase,
            "matchedPods": len(pods),
        },
        container=container,
        previous=previous,
        tail_lines=tailLines,
        since_seconds=sinceSeconds,
        limit_bytes=limitBytes,
        timestamps=timestamps,
    )


@app.get(
    "/v1/kubernetes/namespaces/{namespace}/deployments/{name}/logs",
    response_model=PodLogsResponse,
    tags=["kubernetes", "logs"],
)
def get_latest_deployment_pod_logs(
    namespace: Annotated[str, Path(pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")],
    name: Annotated[str, Path(pattern=r"^[a-z0-9]([-.a-z0-9]*[a-z0-9])?$")],
    phase: str | None = Query(default=None, pattern=r"^(Pending|Running|Succeeded|Failed|Unknown)$"),
    container: str | None = Query(default=None, pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"),
    previous: bool = Query(default=False),
    tailLines: int | None = Query(default=LOG_QUERY_DEFAULT_TAIL_LINES, ge=1, le=LOG_QUERY_MAX_TAIL_LINES),
    sinceSeconds: int | None = Query(default=None, ge=1, le=86400),
    limitBytes: int | None = Query(default=LOG_QUERY_DEFAULT_LIMIT_BYTES, ge=1, le=LOG_QUERY_MAX_LIMIT_BYTES),
    timestamps: bool = Query(default=False),
) -> PodLogsResponse:
    _require_namespace_allowed_for_kubernetes_query(namespace)
    pods, label_selector = _pods_for_workload(namespace, "Deployment", name)
    if phase:
        pods = [pod for pod in pods if _dict_or_empty(pod.get("status")).get("phase") == phase]
    pod = _select_latest_pod(pods)
    pod_name = _dict_or_empty(pod.get("metadata")).get("name")
    if not isinstance(pod_name, str):
        raise HTTPException(status_code=502, detail={"message": "Selected pod did not include a name."})
    return _build_pod_logs_response(
        namespace,
        pod_name,
        selection={
            "mode": "deployment",
            "deployment": name,
            "labelSelector": label_selector,
            "phase": phase,
            "matchedPods": len(pods),
        },
        container=container,
        previous=previous,
        tail_lines=tailLines,
        since_seconds=sinceSeconds,
        limit_bytes=limitBytes,
        timestamps=timestamps,
    )


@app.get(
    "/v1/kubernetes/namespaces/{namespace}/pods/{pod}/logs",
    response_model=PodLogsResponse,
    tags=["kubernetes", "logs"],
)
def get_pod_logs(
    namespace: Annotated[str, Path(pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")],
    pod: Annotated[str, Path(pattern=r"^[a-z0-9]([-.a-z0-9]*[a-z0-9])?$")],
    container: str | None = Query(default=None, pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"),
    previous: bool = Query(default=False),
    tailLines: int | None = Query(default=LOG_QUERY_DEFAULT_TAIL_LINES, ge=1, le=LOG_QUERY_MAX_TAIL_LINES),
    sinceSeconds: int | None = Query(default=None, ge=1, le=86400),
    limitBytes: int | None = Query(default=LOG_QUERY_DEFAULT_LIMIT_BYTES, ge=1, le=LOG_QUERY_MAX_LIMIT_BYTES),
    timestamps: bool = Query(default=False),
) -> PodLogsResponse:
    _require_namespace_allowed_for_kubernetes_query(namespace)
    return _build_pod_logs_response(
        namespace,
        pod,
        selection={"mode": "pod", "pod": pod},
        container=container,
        previous=previous,
        tail_lines=tailLines,
        since_seconds=sinceSeconds,
        limit_bytes=limitBytes,
        timestamps=timestamps,
    )


@app.get(
    "/v1/argocd/applications/{name}",
    response_model=ArgoCDApplicationResponse,
    tags=["argocd"],
)
def get_argocd_application(
    name: Annotated[str, Path(pattern=r"^[a-z0-9]([-.a-z0-9]*[a-z0-9])?$")],
) -> ArgoCDApplicationResponse:
    payload = _kubernetes_json_request(
        "GET",
        f"/apis/argoproj.io/v1alpha1/namespaces/{ARGOCD_APPLICATION_NAMESPACE}/applications/{name}",
        action="reading ArgoCD application status",
    )
    status = _dict_or_empty(payload.get("status"))
    sync = _dict_or_empty(status.get("sync"))
    health = _dict_or_empty(status.get("health"))
    operation_state = status.get("operationState") if isinstance(status.get("operationState"), dict) else None
    revision = sync.get("revision")
    if not isinstance(revision, str):
        revision = None
    return ArgoCDApplicationResponse(
        ok=True,
        name=name,
        namespace=ARGOCD_APPLICATION_NAMESPACE,
        sync=sync,
        health=health,
        operationState=operation_state,
        revision=revision,
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
