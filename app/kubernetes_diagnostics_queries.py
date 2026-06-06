from __future__ import annotations

import glob
import os
from typing import Any

from fastapi import HTTPException

from .kubernetes_diagnostics_client import _kubernetes_json_request, _kubernetes_request, _response_error_body
from .kubernetes_diagnostics_models import (
    LOG_QUERY_ALLOW_LOCAL_FALLBACK,
    LOG_QUERY_DEFAULT_LIMIT_BYTES,
    LOG_QUERY_DEFAULT_TAIL_LINES,
    LOG_QUERY_LOCAL_ROOT,
    LOG_QUERY_MAX_LIMIT_BYTES,
    LOG_QUERY_MAX_TAIL_LINES,
    LOG_REDACTION_RULES,
    PodLogsResponse,
    _dict_or_empty,
    _event_sort_key,
    _event_summary,
    _list_or_empty,
    _rotation_index,
)


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


def _local_pod_log_files(namespace: str, pod: str, container: str | None, previous: bool) -> list[str]:
    pod_dirs = [path for path in glob.glob(os.path.join(LOG_QUERY_LOCAL_ROOT, f"{namespace}_{pod}_*")) if os.path.isdir(path)]
    if not pod_dirs:
        return []

    pod_dir = max(pod_dirs, key=os.path.getmtime)
    if container:
        container_dirs = [os.path.join(pod_dir, container)] if os.path.isdir(os.path.join(pod_dir, container)) else []
    else:
        container_dirs = [path for path in glob.glob(os.path.join(pod_dir, "*")) if os.path.isdir(path)]
        if len(container_dirs) > 1:
            raise HTTPException(status_code=400, detail="Container is required when the pod has more than one container.")

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


def _finalize_log_text(text: str, *, tail_lines: int | None, limit_bytes: int | None) -> tuple[str, bool, bool]:
    redacted_text = text
    redacted = False
    for pattern, replacement in LOG_REDACTION_RULES:
        redacted_text, count = pattern.subn(replacement, redacted_text)
        redacted = redacted or count > 0
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
    resource = "deployments" if kind == "Deployment" else "statefulsets" if kind == "StatefulSet" else "jobs"
    api_prefix = "/apis/apps/v1" if kind in {"Deployment", "StatefulSet"} else "/apis/batch/v1"
    return _kubernetes_json_request(
        "GET",
        f"{api_prefix}/namespaces/{namespace}/{resource}/{name}",
        action=f"reading {kind.lower()} status",
    )


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


def _is_pod_ready(pod: dict[str, Any]) -> bool:
    status = _dict_or_empty(pod.get("status"))
    if status.get("phase") != "Running":
        return False
    for condition in _list_or_empty(status.get("conditions")):
        if isinstance(condition, dict) and condition.get("type") == "Ready" and condition.get("status") == "True":
            return True
    return False


def _select_latest_pod(pods: list[dict[str, Any]], *, prefer_ready: bool = False) -> dict[str, Any]:
    if not pods:
        raise HTTPException(status_code=404, detail={"message": "No pods matched the requested selector."})
    if prefer_ready:
        ready_pods = [pod for pod in pods if _is_pod_ready(pod)]
        if ready_pods:
            pods = ready_pods
    return max(pods, key=_pod_sort_key)


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
    events = [item for item in items if isinstance(item, dict)]
    events.sort(key=_event_sort_key, reverse=True)
    return events, params.get("fieldSelector") if isinstance(params.get("fieldSelector"), str) else None


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
        "desiredReplicas": spec.get("replicas", 1) if kind in {"Deployment", "StatefulSet"} else spec.get("parallelism") or spec.get("completions"),
        "readyReplicas": status.get("readyReplicas", 0) if kind in {"Deployment", "StatefulSet"} else status.get("active"),
        "availableReplicas": status.get("availableReplicas", 0) if kind in {"Deployment", "StatefulSet"} else status.get("succeeded"),
        "updatedReplicas": status.get("updatedReplicas", 0) if kind in {"Deployment", "StatefulSet"} else None,
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
) -> PodLogsResponse:
    params = _log_query_params(
        container=container,
        previous=previous,
        tailLines=tail_lines,
        sinceSeconds=since_seconds,
        limitBytes=limit_bytes,
        timestamps=timestamps,
    )
    source = "kubernetes-api"
    backend_error: dict[str, Any] | None = None
    previous_available: bool | None = None
    previous_unavailable_reason: str | None = None
    try:
        response = _kubernetes_request("GET", f"/api/v1/namespaces/{namespace}/pods/{pod}/log", params=params)
        if response.status_code >= 400:
            backend_error = {
                "statusCode": response.status_code,
                "message": _response_error_body(response),
            }
            if previous and response.status_code in {400, 404}:
                previous_unavailable_reason = backend_error["message"]
                logs = ""
                previous_available = False
            else:
                raise HTTPException(
                    status_code=502 if response.status_code >= 500 else 403 if response.status_code in {401, 403} else 404 if response.status_code == 404 else 502,
                    detail={
                        "message": "Kubernetes API returned an error while querying pod logs.",
                        "backendStatusCode": response.status_code,
                        "backendMessage": backend_error["message"],
                    },
                )
        else:
            logs = response.text
    except HTTPException as kubernetes_error:
        if not LOG_QUERY_ALLOW_LOCAL_FALLBACK and not (previous and previous_unavailable_reason):
            raise kubernetes_error
        try:
            logs = _read_local_pod_logs(namespace, pod, container, previous)
            source = "local-node-log-file"
            previous_available = previous
        except FileNotFoundError:
            if previous and previous_unavailable_reason:
                logs = ""
                previous_available = False
            else:
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
        backendError=backend_error,
        previousAvailable=previous_available if previous else None,
        previousUnavailableReason=previous_unavailable_reason,
    )
