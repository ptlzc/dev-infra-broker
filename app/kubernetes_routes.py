from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, Query

from .kubernetes_diagnostics import (
    ARGOCD_APPLICATION_NAMESPACE,
    LOG_QUERY_DEFAULT_LIMIT_BYTES,
    LOG_QUERY_DEFAULT_TAIL_LINES,
    LOG_QUERY_DENIED_NAMESPACE_PREFIXES,
    LOG_QUERY_MAX_LIMIT_BYTES,
    LOG_QUERY_MAX_TAIL_LINES,
    ArgoCDApplicationResponse,
    EventListResponse,
    PodListResponse,
    PodDetailResponse,
    PodLogsResponse,
    WorkloadStatusResponse,
    _build_pod_logs_response,
    _dict_or_empty,
    _event_summary,
    _kubernetes_json_request,
    _list_events_payload,
    _list_pods_payload,
    _pod_detail_response,
    _pods_for_workload,
    _pod_summary,
    _require_namespace_allowed_for_kubernetes_query,
    _select_latest_pod,
    _workload_detail_response,
)


router = APIRouter()


@router.get("/v1/kubernetes/namespaces/{namespace}/pods", response_model=PodListResponse, tags=["kubernetes", "discovery"])
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


@router.get("/v1/kubernetes/namespaces/{namespace}/deployments/{name}", response_model=WorkloadStatusResponse, tags=["kubernetes", "workloads"])
def get_deployment_status(
    namespace: Annotated[str, Path(pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")],
    name: Annotated[str, Path(pattern=r"^[a-z0-9]([-.a-z0-9]*[a-z0-9])?$")],
) -> WorkloadStatusResponse:
    _require_namespace_allowed_for_kubernetes_query(namespace)
    return WorkloadStatusResponse(**_workload_detail_response(namespace, "Deployment", name))


@router.get("/v1/kubernetes/namespaces/{namespace}/statefulsets/{name}", response_model=WorkloadStatusResponse, tags=["kubernetes", "workloads"])
def get_statefulset_status(
    namespace: Annotated[str, Path(pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")],
    name: Annotated[str, Path(pattern=r"^[a-z0-9]([-.a-z0-9]*[a-z0-9])?$")],
) -> WorkloadStatusResponse:
    _require_namespace_allowed_for_kubernetes_query(namespace)
    return WorkloadStatusResponse(**_workload_detail_response(namespace, "StatefulSet", name))


@router.get("/v1/kubernetes/namespaces/{namespace}/deployments/{name}/pods", response_model=PodListResponse, tags=["kubernetes", "discovery"])
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


@router.get("/v1/kubernetes/namespaces/{namespace}/events", response_model=EventListResponse, tags=["kubernetes", "events"])
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
    return EventListResponse(ok=True, namespace=namespace, fieldSelector=field_selector, count=len(summaries), events=summaries)


@router.get("/v1/kubernetes/namespaces/{namespace}/pods/logs", response_model=PodLogsResponse, tags=["kubernetes", "logs"])
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
    pods, field_selector = _list_pods_payload(namespace, label_selector=labelSelector, field_selector=None, phase=phase)
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


@router.get("/v1/kubernetes/namespaces/{namespace}/deployments/{name}/logs", response_model=PodLogsResponse, tags=["kubernetes", "logs"])
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


@router.get("/v1/kubernetes/namespaces/{namespace}/pods/{pod}/logs", response_model=PodLogsResponse, tags=["kubernetes", "logs"])
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


@router.get("/v1/kubernetes/namespaces/{namespace}/pods/{pod}", response_model=PodDetailResponse, tags=["kubernetes", "discovery"])
def get_pod_detail(
    namespace: Annotated[str, Path(pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")],
    pod: Annotated[str, Path(pattern=r"^[a-z0-9]([-.a-z0-9]*[a-z0-9])?$")],
    pendingTimeoutSeconds: int | None = Query(default=None, ge=1, le=86400),
    terminatingTimeoutSeconds: int | None = Query(default=None, ge=1, le=86400),
) -> PodDetailResponse:
    _require_namespace_allowed_for_kubernetes_query(namespace)
    return PodDetailResponse(**_pod_detail_response(
        namespace,
        pod,
        pending_timeout_seconds=pendingTimeoutSeconds,
        terminating_timeout_seconds=terminatingTimeoutSeconds,
    ))


@router.get("/v1/argocd/applications/{name}", response_model=ArgoCDApplicationResponse, tags=["argocd"])
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
