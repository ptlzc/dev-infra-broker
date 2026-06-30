from __future__ import annotations

from .kubernetes_diagnostics import (
    ARGOCD_APPLICATION_NAMESPACE,
    LOG_QUERY_ALLOW_LOCAL_FALLBACK,
    LOG_QUERY_DEFAULT_LIMIT_BYTES,
    LOG_QUERY_DEFAULT_TAIL_LINES,
    LOG_QUERY_DENIED_NAMESPACE_PREFIXES,
    LOG_QUERY_LOCAL_ROOT,
    LOG_QUERY_MAX_LIMIT_BYTES,
    LOG_QUERY_MAX_TAIL_LINES,
)
from .platform_services import GITHUB_ACTIONS_SYNC_KEYS, Generator, PLATFORM_SECRET_KEYS


def capabilities_payload() -> dict[str, object]:
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
        "domains": [
            {
                "name": "platform-secret",
                "description": "Vault-backed platform secret status and sync helpers.",
                "interfaces": [
                    "GET /v1/platform/secrets/status",
                    "POST /v1/runtime-secret-sets/ensure",
                    "POST /v1/github/repositories/{owner}/{repo}/actions-secrets/sync",
                ],
                "permissions": [
                    "Vault KV read/write for platform secret material",
                    "GitHub repository secret write access through GH_PAT",
                ],
            },
            {
                "name": "project-secret-reader",
                "description": "Bearer-token-authenticated read access for external applications to retrieve specific keys from project runtime secrets.",
                "interfaces": [
                    "POST /v1/project-secrets/read",
                ],
                "permissions": [
                    "Vault KV read for projects/<namespace>/<serviceAccountName>/env",
                    "Requires Bearer token (PROJECT_SECRET_READER_TOKEN env var)",
                    "Returns only requested keys; audit-logged to stdout",
                ],
            },
            {
                "name": "core-observability",
                "description": "Read-only Kubernetes and ArgoCD observability for pods, workloads, logs, events, and applications.",
                "interfaces": [
                    "GET /v1/kubernetes/namespaces/<namespace>/pods",
                    "GET /v1/kubernetes/namespaces/<namespace>/pods/<pod>",
                    "GET /v1/kubernetes/namespaces/<namespace>/deployments/<name>",
                    "GET /v1/kubernetes/namespaces/<namespace>/statefulsets/<name>",
                    "GET /v1/kubernetes/namespaces/<namespace>/deployments/<name>/pods",
                    "GET /v1/kubernetes/namespaces/<namespace>/events",
                    "GET /v1/kubernetes/namespaces/<namespace>/pods/<pod>/logs",
                    "GET /v1/kubernetes/namespaces/<namespace>/deployments/<name>/logs",
                    "GET /v1/kubernetes/namespaces/<namespace>/pods/logs?labelSelector=<selector>",
                    "GET /v1/argocd/applications/<name>",
                ],
                "permissions": [
                    "Kubernetes read access to pods, pods/log, events, deployments, statefulsets, and ArgoCD applications",
                    "Namespace policy: non-system application namespaces only",
                ],
            },
            {
                "name": "workload-intelligence",
                "description": "Job and Dagster run correlation helpers isolated from the core observability surface.",
                "interfaces": [
                    "GET /v1/kubernetes/namespaces/<namespace>/jobs",
                    "GET /v1/kubernetes/namespaces/<namespace>/jobs/<name>",
                    "GET /v1/kubernetes/namespaces/<namespace>/dagster/runs/<runId>",
                ],
                "permissions": [
                    "Kubernetes read access to batch jobs and related pod correlation",
                    "Namespace policy: non-system application namespaces only",
                ],
            },
        ],
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
            "localFallback": {
                "enabled": LOG_QUERY_ALLOW_LOCAL_FALLBACK,
                "root": LOG_QUERY_LOCAL_ROOT,
            },
        },
        "rules": [
            "Broker clients never receive Vault paths or Vault tokens.",
            "Broker responses never include secret values.",
            "GitHub Actions secret sync never exports GH_PAT to target repositories.",
            "Runtime generated secrets are generated only when absent to avoid unintended rotation.",
        ],
    }
