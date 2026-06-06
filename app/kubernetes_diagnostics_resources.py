from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException

from .kubernetes_diagnostics_client import _kubernetes_json_request
from .kubernetes_diagnostics_extra_models import (
    JobListResponse,
    JobSummary,
    PodDetailResponse,
    RunCorrelationJobSummary,
    RunCorrelationPodSummary,
    RunCorrelationResponse,
)
from .kubernetes_diagnostics_models import (
    DAGSTER_CODE_LOCATION_KEYS,
    DAGSTER_JOB_NAME_KEYS,
    DAGSTER_RUN_ID_ANNOTATION_KEYS,
    DAGSTER_RUN_ID_LABEL_KEYS,
    DAGSTER_RUN_TAG_PREFIXES,
    LOG_QUERY_ALLOW_LOCAL_FALLBACK,
    LOG_QUERY_DEFAULT_TAIL_LINES,
    LOG_QUERY_MAX_LIMIT_BYTES,
    LOG_QUERY_MAX_TAIL_LINES,
    WorkloadStatusResponse,
    _condition_summary,
    _container_state_summary,
    _container_status_summary,
    _dict_or_empty,
    _event_summary,
    _job_failure_summary,
    _list_or_empty,
    _pod_container_detail,
    _pod_failure_summary,
    _pod_owner_chain,
    _pod_summary,
    _sanitized_annotations,
    _sanitize_dict,
    _sanitize_freeform_text,
    _sanitize_list,
    _normalize_timestamp,
)
from .kubernetes_diagnostics_queries import (
    _build_pod_logs_response,
    _list_events_payload,
    _list_pods_payload,
    _pods_for_workload,
    _pod_sort_key,
    _select_latest_pod,
    _workload_payload,
    _workload_status_summary,
)


def _list_jobs_payload(namespace: str) -> list[dict[str, Any]]:
    payload = _kubernetes_json_request(
        "GET",
        f"/apis/batch/v1/namespaces/{namespace}/jobs",
        action="listing jobs",
    )
    items = payload.get("items", [])
    if not isinstance(items, list):
        raise HTTPException(status_code=502, detail={"message": "Kubernetes job list response was invalid."})
    return [item for item in items if isinstance(item, dict)]


def _job_payload(namespace: str, name: str) -> dict[str, Any]:
    return _kubernetes_json_request(
        "GET",
        f"/apis/batch/v1/namespaces/{namespace}/jobs/{name}",
        action="reading job status",
    )


def _pod_payload(namespace: str, name: str) -> dict[str, Any]:
    return _kubernetes_json_request(
        "GET",
        f"/api/v1/namespaces/{namespace}/pods/{name}",
        action="reading pod status",
    )


def _job_pods_payload(namespace: str, job_name: str) -> list[dict[str, Any]]:
    selectors = [
        f"job-name={job_name}",
        f"batch.kubernetes.io/job-name={job_name}",
    ]
    pods_by_name: dict[str, dict[str, Any]] = {}
    for selector in selectors:
        pods, _ = _list_pods_payload(namespace, label_selector=selector, field_selector=None, phase=None)
        for pod in pods:
            metadata = _dict_or_empty(pod.get("metadata"))
            name = metadata.get("name")
            if not isinstance(name, str):
                continue
            owner_refs = _pod_owner_chain(pod)
            if owner_refs and not any(ref.get("kind") == "Job" and ref.get("name") == job_name for ref in owner_refs):
                continue
            pods_by_name[name] = pod
    return sorted(pods_by_name.values(), key=_pod_sort_key)


def _workload_pods(namespace: str, kind: str, name: str) -> list[dict[str, Any]]:
    if kind == "Job":
        return _job_pods_payload(namespace, name)
    pods, _ = _pods_for_workload(namespace, kind, name)
    return pods


def _workload_selected_pod(namespace: str, kind: str, name: str) -> dict[str, Any] | None:
    pods = _workload_pods(namespace, kind, name)
    if not pods:
        return None
    if kind in {"Deployment", "StatefulSet"}:
        return _select_latest_pod(pods, prefer_ready=True)
    return _select_latest_pod(pods)


def _workload_failure_summary(namespace: str, kind: str, name: str, pods: list[dict[str, Any]], *, pending_timeout_seconds: int | None = None, terminating_timeout_seconds: int | None = None) -> dict[str, Any]:
    workload = _job_payload(namespace, name) if kind == "Job" else _workload_payload(namespace, kind, name)
    status = _dict_or_empty(workload.get("status"))
    pod_issues: list[dict[str, Any]] = []
    recent_events, _ = _list_events_payload(namespace, involved_object_kind=kind, involved_object_name=name)
    selected_pod = None
    now = datetime.now(timezone.utc)
    if pods:
        selected_pod = _select_latest_pod(pods, prefer_ready=kind in {"Deployment", "StatefulSet"})
        pod_issues.extend(_pod_failure_summary(selected_pod).get("issues", []))
    if kind == "Job":
        active = int(status.get("active") or 0)
        if active and not status.get("succeeded") and not status.get("failed"):
            no_progress = not any(_dict_or_empty(pod.get("status")).get("phase") == "Running" for pod in pods)
            if no_progress:
                pod_issues.append({"kind": "job-progress", "reason": "ActiveWithoutProgress"})
    for pod in pods:
        pod_status = _dict_or_empty(pod.get("status"))
        meta = _dict_or_empty(pod.get("metadata"))
        creation = _normalize_timestamp(meta.get("creationTimestamp"))
        deletion = _normalize_timestamp(meta.get("deletionTimestamp"))
        if (
            pending_timeout_seconds
            and pod_status.get("phase") == "Pending"
            and creation
            and (now - creation).total_seconds() >= pending_timeout_seconds
        ):
            pod_issues.append({"kind": "timeout", "reason": "PendingTimeout", "pod": meta.get("name")})
        if (
            terminating_timeout_seconds
            and deletion
            and (now - deletion).total_seconds() >= terminating_timeout_seconds
        ):
            pod_issues.append({"kind": "timeout", "reason": "TerminatingTimeout", "pod": meta.get("name")})
    last_terminated_reason = None
    if selected_pod:
        for container_status in _list_or_empty(_dict_or_empty(selected_pod.get("status")).get("containerStatuses")):
            if not isinstance(container_status, dict):
                continue
            last_state = _dict_or_empty(container_status.get("lastState"))
            terminated = _dict_or_empty(last_state.get("terminated"))
            if terminated.get("reason"):
                last_terminated_reason = terminated.get("reason")
                break
    return {
        "issues": pod_issues or _job_failure_summary(workload).get("issues", []),
        "recentEvents": [_event_summary(event) for event in recent_events[:5]],
        "lastTerminationReason": last_terminated_reason,
    }


def _diagnostic_links(namespace: str, pod_name: str | None) -> dict[str, str] | None:
    if not isinstance(pod_name, str):
        return None
    return {
        "currentLogs": f"/v1/kubernetes/namespaces/{namespace}/pods/{pod_name}/logs",
        "previousLogs": f"/v1/kubernetes/namespaces/{namespace}/pods/{pod_name}/logs?previous=true",
    }


def _pod_detail_response(namespace: str, pod_name: str, *, pending_timeout_seconds: int | None = None, terminating_timeout_seconds: int | None = None) -> dict[str, Any]:
    payload = _pod_payload(namespace, pod_name)
    recent_events, _ = _list_events_payload(
        namespace,
        involved_object_kind="Pod",
        involved_object_name=pod_name,
        involved_object_uid=_dict_or_empty(payload.get("metadata")).get("uid"),
    )
    failure_summary = {
        **_pod_failure_summary(payload),
        "recentEvents": [_event_summary(event) for event in recent_events[:5]],
        "lastTerminationReason": next(
            (
                _dict_or_empty(_dict_or_empty(container_status.get("lastState")).get("terminated")).get("reason")
                for container_status in _list_or_empty(_dict_or_empty(payload.get("status")).get("containerStatuses"))
                if isinstance(container_status, dict)
                and _dict_or_empty(_dict_or_empty(container_status.get("lastState")).get("terminated")).get("reason")
            ),
            None,
        ),
    }
    detail = {
        "ok": True,
        "namespace": namespace,
        "name": pod_name,
        "phase": _dict_or_empty(payload.get("status")).get("phase"),
        "nodeName": _dict_or_empty(payload.get("spec")).get("nodeName"),
        "podIP": _dict_or_empty(payload.get("status")).get("podIP"),
        "hostIP": _dict_or_empty(payload.get("status")).get("hostIP"),
        "ownerReferences": _pod_owner_chain(payload),
        "labels": _sanitize_dict(_dict_or_empty(payload.get("metadata")).get("labels"), redact_sensitive_keys=False),
        "annotations": _sanitized_annotations(_dict_or_empty(payload.get("metadata"))),
        "containerStatuses": [_container_status_summary(item) for item in _list_or_empty(_dict_or_empty(payload.get("status")).get("containerStatuses")) if isinstance(item, dict)],
        "initContainerStatuses": [_container_status_summary(item) for item in _list_or_empty(_dict_or_empty(payload.get("status")).get("initContainerStatuses")) if isinstance(item, dict)],
        "containers": [
            _pod_container_detail(container, next((s for s in _list_or_empty(_dict_or_empty(payload.get("status")).get("containerStatuses")) if isinstance(s, dict) and s.get("name") == container.get("name")), None))
            for container in _list_or_empty(_dict_or_empty(payload.get("spec")).get("containers"))
            if isinstance(container, dict)
        ],
        "initContainers": [
            _pod_container_detail(container, next((s for s in _list_or_empty(_dict_or_empty(payload.get("status")).get("initContainerStatuses")) if isinstance(s, dict) and s.get("name") == container.get("name")), None))
            for container in _list_or_empty(_dict_or_empty(payload.get("spec")).get("initContainers"))
            if isinstance(container, dict)
        ],
        "restartCount": sum(
            status.get("restartCount", 0)
            for status in _list_or_empty(_dict_or_empty(payload.get("status")).get("containerStatuses")) + _list_or_empty(_dict_or_empty(payload.get("status")).get("initContainerStatuses"))
            if isinstance(status, dict)
        ),
        "conditions": [_condition_summary(condition) for condition in _list_or_empty(_dict_or_empty(payload.get("status")).get("conditions")) if isinstance(condition, dict)],
        "events": [_event_summary(event) for event in recent_events[:10]],
        "failureSummary": failure_summary,
        "diagnosticLinks": _diagnostic_links(namespace, pod_name),
        "creationTimestamp": _dict_or_empty(payload.get("metadata")).get("creationTimestamp"),
        "startTime": _dict_or_empty(payload.get("status")).get("startTime"),
    }
    return detail


def _job_summary(namespace: str, job: dict[str, Any]) -> dict[str, Any]:
    metadata = _dict_or_empty(job.get("metadata"))
    status = _dict_or_empty(job.get("status"))
    name = metadata.get("name")
    pods = _job_pods_payload(namespace, name) if isinstance(name, str) else []
    return {
        "jobName": name,
        "namespace": namespace,
        "active": status.get("active"),
        "succeeded": status.get("succeeded"),
        "failed": status.get("failed"),
        "startTime": status.get("startTime"),
        "completionTime": status.get("completionTime"),
        "ownerReferences": _pod_owner_chain(job),
        "labels": _sanitize_dict(metadata.get("labels"), redact_sensitive_keys=False),
        "podCount": len(pods),
        "failureSummary": _workload_failure_summary(namespace, "Job", name, pods) if isinstance(name, str) else None,
    }


def _job_list_response(namespace: str) -> dict[str, Any]:
    jobs = [_job_summary(namespace, job) for job in _list_jobs_payload(namespace)]
    return {"ok": True, "namespace": namespace, "count": len(jobs), "jobs": jobs}


def _workload_detail_response(namespace: str, kind: str, name: str, *, pending_timeout_seconds: int | None = None, terminating_timeout_seconds: int | None = None) -> dict[str, Any]:
    pods = _workload_pods(namespace, kind, name)
    selected = _workload_selected_pod(namespace, kind, name)
    selected_name = _dict_or_empty(selected.get("metadata")).get("name") if selected else None
    selected_summary = _pod_summary(selected) if selected else None
    return {
        **_workload_status_summary(namespace, kind, name),
        "pods": [_pod_summary(pod) for pod in pods],
        "selectedPod": selected_summary,
        "failureSummary": _workload_failure_summary(namespace, kind, name, pods, pending_timeout_seconds=pending_timeout_seconds, terminating_timeout_seconds=terminating_timeout_seconds),
        "diagnosticLinks": _diagnostic_links(namespace, selected_name if isinstance(selected_name, str) else None),
    }


def _run_identity(metadata: dict[str, Any]) -> dict[str, Any]:
    labels = _sanitize_dict(metadata.get("labels"), redact_sensitive_keys=False)
    annotations = _sanitized_annotations(metadata)
    def first(keys: tuple[str, ...]) -> str | None:
        for key in keys:
            value = labels.get(key) or annotations.get(key)
            if isinstance(value, str) and value:
                return value
        return None
    run_tags = {}
    for source in (labels, annotations):
        for key, value in source.items():
            if any(key.startswith(prefix) for prefix in DAGSTER_RUN_TAG_PREFIXES) and isinstance(value, str):
                run_tags[key] = value
    return {
        "runId": first(DAGSTER_RUN_ID_LABEL_KEYS) or first(DAGSTER_RUN_ID_ANNOTATION_KEYS),
        "jobName": first(DAGSTER_JOB_NAME_KEYS),
        "codeLocation": first(DAGSTER_CODE_LOCATION_KEYS),
        "runTags": run_tags,
    }


def _run_correlation_response(namespace: str, run_id: str) -> dict[str, Any]:
    jobs = []
    pods = []
    all_pods, _ = _list_pods_payload(namespace, label_selector=None, field_selector=None, phase=None)
    pod_identities = []
    for pod in all_pods:
        pmeta = _dict_or_empty(pod.get("metadata"))
        identity = _run_identity(pmeta)
        pod_identities.append((pod, identity))
    for job in _list_jobs_payload(namespace):
        metadata = _dict_or_empty(job.get("metadata"))
        identity = _run_identity(metadata)
        job_name = metadata.get("name")
        matched_pods = []
        if isinstance(job_name, str):
            matched_pods = [
                pod
                for pod, pod_identity in pod_identities
                if pod_identity.get("runId") == run_id
                and any(
                    ref.get("kind") == "Job" and ref.get("name") == job_name
                    for ref in _pod_owner_chain(pod)
                )
            ]
        if identity.get("runId") != run_id and not matched_pods:
            continue
        job_pods = _job_pods_payload(namespace, job_name) if isinstance(job_name, str) else []
        if not job_pods:
            job_pods = matched_pods
        jobs.append(
            {
                "jobName": job_name,
                "namespace": namespace,
                "active": _dict_or_empty(job.get("status")).get("active"),
                "succeeded": _dict_or_empty(job.get("status")).get("succeeded"),
                "failed": _dict_or_empty(job.get("status")).get("failed"),
                "podCount": len(job_pods),
                "failureSummary": _workload_failure_summary(namespace, "Job", job_name, job_pods) if isinstance(job_name, str) else None,
            }
            )
        for pod in job_pods:
            pmeta = _dict_or_empty(pod.get("metadata"))
            pstatus = _dict_or_empty(pod.get("status"))
            pname = pmeta.get("name")
            if not isinstance(pname, str):
                continue
            pod_summary = _pod_summary(pod)
            pods.append(
                {
                    "podName": pname,
                    "namespace": namespace,
                    "phase": pstatus.get("phase"),
                    "restartCount": pod_summary.get("restartCount"),
                    "containerStatuses": pod_summary.get("containerStatuses"),
                    "ownerReferences": _pod_owner_chain(pod),
                    "failureSummary": _pod_failure_summary(pod),
                    "currentLogLink": f"/v1/kubernetes/namespaces/{namespace}/pods/{pname}/logs",
                    "previousLogLink": f"/v1/kubernetes/namespaces/{namespace}/pods/{pname}/logs?previous=true",
                }
            )
    for pod, pod_identity in pod_identities:
        if pod_identity.get("runId") != run_id:
            continue
        pmeta = _dict_or_empty(pod.get("metadata"))
        pname = pmeta.get("name")
        if not isinstance(pname, str):
            continue
        if any(existing.get("podName") == pname for existing in pods):
            continue
        pstatus = _dict_or_empty(pod.get("status"))
        pod_summary = _pod_summary(pod)
        pods.append(
            {
                "podName": pname,
                "namespace": namespace,
                "phase": pstatus.get("phase"),
                "restartCount": pod_summary.get("restartCount"),
                "containerStatuses": pod_summary.get("containerStatuses"),
                "ownerReferences": _pod_owner_chain(pod),
                "failureSummary": _pod_failure_summary(pod),
                "currentLogLink": f"/v1/kubernetes/namespaces/{namespace}/pods/{pname}/logs",
                "previousLogLink": f"/v1/kubernetes/namespaces/{namespace}/pods/{pname}/logs?previous=true",
            }
        )
    unique_pods = {pod["podName"]: pod for pod in pods if pod.get("podName")}
    return {
        "ok": True,
        "namespace": namespace,
        "runId": run_id,
        "jobs": jobs,
        "pods": list(unique_pods.values()),
        "count": len(jobs) + len(unique_pods),
    }
