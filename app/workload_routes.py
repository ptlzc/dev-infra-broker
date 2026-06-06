from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Path, Query

from .kubernetes_diagnostics import (
    JobListResponse,
    RunCorrelationResponse,
    WorkloadStatusResponse,
    _require_namespace_allowed_for_kubernetes_query,
    _run_correlation_response,
    _job_list_response,
    _workload_detail_response,
)


router = APIRouter()


@router.get("/v1/kubernetes/namespaces/{namespace}/jobs", response_model=JobListResponse, tags=["kubernetes", "jobs"])
def list_jobs(
    namespace: Annotated[str, Path(pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")],
) -> JobListResponse:
    _require_namespace_allowed_for_kubernetes_query(namespace)
    return JobListResponse(**_job_list_response(namespace))


@router.get("/v1/kubernetes/namespaces/{namespace}/jobs/{name}", response_model=WorkloadStatusResponse, tags=["kubernetes", "jobs"])
def get_job_status(
    namespace: Annotated[str, Path(pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")],
    name: Annotated[str, Path(pattern=r"^[a-z0-9]([-.a-z0-9]*[a-z0-9])?$")],
    pendingTimeoutSeconds: int | None = Query(default=None, ge=1, le=86400),
    terminatingTimeoutSeconds: int | None = Query(default=None, ge=1, le=86400),
) -> WorkloadStatusResponse:
    _require_namespace_allowed_for_kubernetes_query(namespace)
    return WorkloadStatusResponse(**_workload_detail_response(
        namespace,
        "Job",
        name,
        pending_timeout_seconds=pendingTimeoutSeconds,
        terminating_timeout_seconds=terminatingTimeoutSeconds,
    ))


@router.get("/v1/kubernetes/namespaces/{namespace}/dagster/runs/{runId}", response_model=RunCorrelationResponse, tags=["kubernetes", "dagster"])
def get_run_correlation(
    namespace: Annotated[str, Path(pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")],
    runId: Annotated[str, Path(min_length=1, max_length=128)],
) -> RunCorrelationResponse:
    _require_namespace_allowed_for_kubernetes_query(namespace)
    return RunCorrelationResponse(**_run_correlation_response(namespace, runId))
