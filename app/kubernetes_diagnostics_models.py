from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException
from pydantic import BaseModel


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
LOG_QUERY_ALLOW_LOCAL_FALLBACK = os.getenv("LOG_QUERY_ALLOW_LOCAL_FALLBACK", "true").lower() in {"1", "true", "yes", "on"}
LOG_QUERY_LOCAL_ROOT = os.getenv("LOG_QUERY_LOCAL_ROOT", "/host/var/log/pods").rstrip("/")
ARGOCD_APPLICATION_NAMESPACE = os.getenv("ARGOCD_APPLICATION_NAMESPACE", "argocd")
DAGSTER_RUN_ID_LABEL_KEYS = tuple(
    key.strip()
    for key in os.getenv(
        "DAGSTER_RUN_ID_LABEL_KEYS",
        "dagster.io/run-id,dagster_run_id,dagster.run_id",
    ).split(",")
    if key.strip()
)
DAGSTER_RUN_ID_ANNOTATION_KEYS = tuple(
    key.strip()
    for key in os.getenv(
        "DAGSTER_RUN_ID_ANNOTATION_KEYS",
        "dagster.io/run-id,dagster_run_id,dagster.run_id",
    ).split(",")
    if key.strip()
)
DAGSTER_JOB_NAME_KEYS = tuple(
    key.strip()
    for key in os.getenv(
        "DAGSTER_JOB_NAME_KEYS",
        "dagster.io/job-name,dagster_job_name,dagster.job_name",
    ).split(",")
    if key.strip()
)
DAGSTER_CODE_LOCATION_KEYS = tuple(
    key.strip()
    for key in os.getenv(
        "DAGSTER_CODE_LOCATION_KEYS",
        "dagster.io/code-location,dagster_code_location,dagster.code_location",
    ).split(",")
    if key.strip()
)
DAGSTER_RUN_TAG_PREFIXES = tuple(
    prefix.strip()
    for prefix in os.getenv(
        "DAGSTER_RUN_TAG_PREFIXES",
        "dagster.io/tag.,dagster-tag.,dagster.run.tag.",
    ).split(",")
    if prefix.strip()
)
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
SENSITIVE_KEY_PATTERN = re.compile(r"(?i)(secret|token|password|passwd|api[-_]?key|client[-_]?secret)")


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


def _normalize_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        normalized = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _sort_timestamp_value(item: dict[str, Any]) -> datetime:
    metadata = _dict_or_empty(item.get("metadata"))
    status = _dict_or_empty(item.get("status"))
    for candidate in (
        metadata.get("creationTimestamp"),
        status.get("startTime"),
        status.get("completionTime"),
    ):
        parsed = _normalize_timestamp(candidate)
        if parsed is not None:
            return parsed
    return datetime.min.replace(tzinfo=timezone.utc)


def _event_sort_key(event: dict[str, Any]) -> tuple[datetime, str]:
    metadata = _dict_or_empty(event.get("metadata"))
    ts = _normalize_timestamp(event.get("eventTime")) or _normalize_timestamp(event.get("lastTimestamp")) or _normalize_timestamp(event.get("firstTimestamp"))
    return (ts or datetime.min.replace(tzinfo=timezone.utc), str(metadata.get("name") or ""))


def _sanitize_freeform_text(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    redacted = value
    for pattern, replacement in LOG_REDACTION_RULES:
        redacted, _ = pattern.subn(replacement, redacted)
    return redacted


def _sanitize_dict(value: Any, *, redact_sensitive_keys: bool = False) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    sanitized: dict[str, Any] = {}
    for key, item in value.items():
        if redact_sensitive_keys and isinstance(key, str) and SENSITIVE_KEY_PATTERN.search(key):
            sanitized[key] = "[REDACTED]"
            continue
        sanitized[key] = _sanitize_value(item, redact_sensitive_keys=redact_sensitive_keys)
    return sanitized


def _sanitize_list(value: Any, *, redact_sensitive_keys: bool = False) -> list[Any]:
    if not isinstance(value, list):
        return []
    return [_sanitize_value(item, redact_sensitive_keys=redact_sensitive_keys) for item in value]


def _sanitize_value(value: Any, *, redact_sensitive_keys: bool = False) -> Any:
    if isinstance(value, dict):
        return _sanitize_dict(value, redact_sensitive_keys=redact_sensitive_keys)
    if isinstance(value, list):
        return _sanitize_list(value, redact_sensitive_keys=redact_sensitive_keys)
    return _sanitize_freeform_text(value)


def _list_or_empty(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _dict_or_empty(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _rotation_index(path: str) -> int:
    name = os.path.basename(path)
    number = name.split(".", 1)[0]
    try:
        return int(number)
    except ValueError:
        return 0


def _container_resource_summary(resource: dict[str, Any]) -> dict[str, Any]:
    return {
        "cpu": resource.get("cpu"),
        "memory": resource.get("memory"),
        "ephemeralStorage": resource.get("ephemeral-storage"),
    }


def _volume_mount_summary(container: dict[str, Any]) -> list[dict[str, Any]]:
    mounts = _list_or_empty(container.get("volumeMounts"))
    summaries: list[dict[str, Any]] = []
    for mount in mounts:
        if not isinstance(mount, dict):
            continue
        summaries.append(
            {
                "name": mount.get("name"),
                "mountPath": mount.get("mountPath"),
                "readOnly": mount.get("readOnly"),
                "subPath": mount.get("subPath"),
                "subPathExpr": mount.get("subPathExpr"),
            }
        )
    return summaries


def _container_state_summary(state: Any) -> dict[str, Any]:
    if not isinstance(state, dict):
        return {}
    waiting = state.get("waiting")
    running = state.get("running")
    terminated = state.get("terminated")
    summary: dict[str, Any] = {}
    if isinstance(waiting, dict):
        summary["waiting"] = {
            "reason": waiting.get("reason"),
            "message": _sanitize_freeform_text(waiting.get("message")),
        }
    if isinstance(running, dict):
        summary["running"] = {"startedAt": running.get("startedAt")}
    if isinstance(terminated, dict):
        summary["terminated"] = {
            "reason": terminated.get("reason"),
            "exitCode": terminated.get("exitCode"),
            "signal": terminated.get("signal"),
            "startedAt": terminated.get("startedAt"),
            "finishedAt": terminated.get("finishedAt"),
            "message": _sanitize_freeform_text(terminated.get("message")),
        }
    return summary


def _restart_count(container_statuses: list[dict[str, Any]]) -> int:
    return sum(status.get("restartCount", 0) for status in container_statuses if isinstance(status.get("restartCount", 0), int))


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


def _pod_container_detail(container: dict[str, Any], status: dict[str, Any] | None) -> dict[str, Any]:
    resources = _dict_or_empty(container.get("resources"))
    status_state = _dict_or_empty((status or {}).get("state"))
    last_state = _dict_or_empty((status or {}).get("lastState"))
    return {
        "name": container.get("name"),
        "image": container.get("image"),
        "imagePullPolicy": container.get("imagePullPolicy"),
        "imageID": (status or {}).get("imageID"),
        "ready": (status or {}).get("ready"),
        "restartCount": (status or {}).get("restartCount"),
        "started": (status or {}).get("started"),
        "state": _container_state_summary(status_state),
        "lastState": _container_state_summary(last_state),
        "resources": {
            "requests": _container_resource_summary(_dict_or_empty(resources.get("requests"))),
            "limits": _container_resource_summary(_dict_or_empty(resources.get("limits"))),
        },
        "volumeMounts": _volume_mount_summary(container),
    }


def _condition_summary(condition: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": condition.get("type"),
        "status": condition.get("status"),
        "reason": condition.get("reason"),
        "message": _sanitize_freeform_text(condition.get("message")),
        "lastProbeTime": condition.get("lastProbeTime"),
        "lastTransitionTime": condition.get("lastTransitionTime"),
    }


def _pod_owner_chain(item: dict[str, Any]) -> list[dict[str, Any]]:
    metadata = _dict_or_empty(item.get("metadata"))
    chain = _sanitize_list(metadata.get("ownerReferences"), redact_sensitive_keys=False)
    return [entry for entry in chain if isinstance(entry, dict) and isinstance(entry.get("kind"), str) and isinstance(entry.get("name"), str)]


def _sanitized_annotations(metadata: dict[str, Any]) -> dict[str, Any]:
    annotations = _sanitize_dict(metadata.get("annotations"), redact_sensitive_keys=True)
    return {key: value for key, value in annotations.items() if not SENSITIVE_KEY_PATTERN.search(key)}


def _event_summary(event: dict[str, Any]) -> dict[str, Any]:
    reporting_instance = event.get("reportingInstance")
    reporting_controller = event.get("reportingController")
    related = event.get("related") if isinstance(event.get("related"), dict) else None
    return {
        "name": _dict_or_empty(event.get("metadata")).get("name"),
        "type": event.get("type"),
        "reason": event.get("reason"),
        "message": _sanitize_freeform_text(event.get("message")),
        "count": event.get("count"),
        "firstTimestamp": event.get("firstTimestamp"),
        "lastTimestamp": event.get("lastTimestamp"),
        "eventTime": event.get("eventTime"),
        "involvedObject": _sanitize_dict(event.get("involvedObject"), redact_sensitive_keys=True),
        "reportingSource": {
            "component": event.get("source", {}).get("component") if isinstance(event.get("source"), dict) else None,
            "host": event.get("source", {}).get("host") if isinstance(event.get("source"), dict) else None,
            "reportingController": reporting_controller,
            "reportingInstance": reporting_instance,
        },
        "related": _sanitize_dict(related, redact_sensitive_keys=True) if related else None,
    }


def _pod_summary(pod: dict[str, Any]) -> dict[str, Any]:
    metadata = _dict_or_empty(pod.get("metadata"))
    status = _dict_or_empty(pod.get("status"))
    spec = _dict_or_empty(pod.get("spec"))
    container_statuses = [item for item in _list_or_empty(status.get("containerStatuses")) if isinstance(item, dict)]
    init_container_statuses = [item for item in _list_or_empty(status.get("initContainerStatuses")) if isinstance(item, dict)]
    return {
        "podName": metadata.get("name"),
        "phase": status.get("phase"),
        "restartCount": _restart_count(container_statuses + init_container_statuses),
        "nodeName": spec.get("nodeName"),
        "ownerReferences": _pod_owner_chain(pod),
        "containerStatuses": [_container_status_summary(item) for item in container_statuses],
        "initContainerStatuses": [_container_status_summary(item) for item in init_container_statuses],
        "creationTimestamp": metadata.get("creationTimestamp"),
        "startTime": status.get("startTime"),
        "labels": _sanitize_dict(metadata.get("labels"), redact_sensitive_keys=False),
    }


def _pod_failure_summary(item: dict[str, Any]) -> dict[str, Any]:
    status = _dict_or_empty(item.get("status"))
    summary: dict[str, Any] = {"issues": []}
    for container_status in _list_or_empty(status.get("containerStatuses")):
        if not isinstance(container_status, dict):
            continue
        state = _dict_or_empty(container_status.get("state"))
        waiting = _dict_or_empty(state.get("waiting"))
        terminated = _dict_or_empty(state.get("terminated"))
        last_state = _dict_or_empty(container_status.get("lastState"))
        last_terminated = _dict_or_empty(last_state.get("terminated"))
        for source in (waiting, terminated, last_terminated):
            reason = source.get("reason")
            if reason in {"OOMKilled", "CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", "FailedMount", "FailedScheduling"}:
                summary["issues"].append(
                    {
                        "kind": "container-state",
                        "container": container_status.get("name"),
                        "reason": reason,
                        "message": _sanitize_freeform_text(source.get("message")),
                    }
                )
    for condition in _list_or_empty(status.get("conditions")):
        if not isinstance(condition, dict):
            continue
        if condition.get("status") == "False" and condition.get("reason") in {"Unhealthy", "ContainersNotReady", "PodScheduled"}:
            summary["issues"].append(
                {
                    "kind": "pod-condition",
                    "reason": condition.get("reason"),
                    "message": _sanitize_freeform_text(condition.get("message")),
                }
            )
    if status.get("phase") == "Pending":
        summary["issues"].append({"kind": "phase", "reason": "Pending"})
    if status.get("phase") == "Failed":
        summary["issues"].append({"kind": "phase", "reason": "Failed"})
    return summary


def _job_failure_summary(item: dict[str, Any]) -> dict[str, Any]:
    status = _dict_or_empty(item.get("status"))
    summary = {"issues": [], "active": status.get("active"), "succeeded": status.get("succeeded"), "failed": status.get("failed")}
    if status.get("failed"):
        summary["issues"].append({"kind": "job-status", "reason": "Failed"})
    if status.get("active") and not status.get("succeeded") and not status.get("failed"):
        summary["issues"].append({"kind": "job-status", "reason": "Active"})
    return summary


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
    reportingSource: dict[str, Any] | None = None
    related: dict[str, Any] | None = None


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
    pods: list[dict[str, Any]] | None = None
    selectedPod: dict[str, Any] | None = None
    failureSummary: dict[str, Any] | None = None
    diagnosticLinks: dict[str, Any] | None = None


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
    backendError: dict[str, Any] | None = None
    previousAvailable: bool | None = None
    previousUnavailableReason: str | None = None


class ArgoCDApplicationResponse(BaseModel):
    ok: bool
    name: str
    namespace: str
    sync: dict[str, Any]
    health: dict[str, Any]
    operationState: dict[str, Any] | None
    revision: str | None
