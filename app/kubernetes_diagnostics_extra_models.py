from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class PodDetailResponse(BaseModel):
    ok: bool
    namespace: str
    name: str
    phase: str | None
    nodeName: str | None
    podIP: str | None
    hostIP: str | None
    ownerReferences: list[dict[str, Any]]
    labels: dict[str, Any]
    annotations: dict[str, Any]
    containerStatuses: list[dict[str, Any]]
    initContainerStatuses: list[dict[str, Any]]
    containers: list[dict[str, Any]]
    initContainers: list[dict[str, Any]]
    restartCount: int
    conditions: list[dict[str, Any]]
    events: list[dict[str, Any]]
    failureSummary: dict[str, Any] | None = None
    diagnosticLinks: dict[str, Any] | None = None
    creationTimestamp: str | None = None
    startTime: str | None = None


class JobSummary(BaseModel):
    jobName: str | None
    namespace: str
    active: int | None
    succeeded: int | None
    failed: int | None
    startTime: str | None
    completionTime: str | None
    ownerReferences: list[dict[str, Any]]
    labels: dict[str, Any]
    podCount: int
    failureSummary: dict[str, Any] | None = None


class JobListResponse(BaseModel):
    ok: bool
    namespace: str
    count: int
    jobs: list[JobSummary]


class RunCorrelationPodSummary(BaseModel):
    podName: str | None
    namespace: str
    phase: str | None
    restartCount: int
    containerStatuses: list[dict[str, Any]]
    ownerReferences: list[dict[str, Any]]
    failureSummary: dict[str, Any] | None = None
    currentLogLink: str | None = None
    previousLogLink: str | None = None


class RunCorrelationJobSummary(BaseModel):
    jobName: str | None
    namespace: str
    active: int | None
    succeeded: int | None
    failed: int | None
    podCount: int
    failureSummary: dict[str, Any] | None = None


class RunCorrelationResponse(BaseModel):
    ok: bool
    namespace: str
    runId: str
    jobs: list[RunCorrelationJobSummary]
    pods: list[RunCorrelationPodSummary]
    count: int
