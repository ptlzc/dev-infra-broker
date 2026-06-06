from fastapi import FastAPI

from .kubernetes_diagnostics import (
    ARGOCD_APPLICATION_NAMESPACE,
    DAGSTER_CODE_LOCATION_KEYS,
    DAGSTER_JOB_NAME_KEYS,
    DAGSTER_RUN_ID_ANNOTATION_KEYS,
    DAGSTER_RUN_ID_LABEL_KEYS,
    DAGSTER_RUN_TAG_PREFIXES,
    LOG_QUERY_ALLOW_LOCAL_FALLBACK,
    LOG_QUERY_DEFAULT_LIMIT_BYTES,
    LOG_QUERY_DEFAULT_TAIL_LINES,
    LOG_QUERY_DENIED_NAMESPACE_PREFIXES,
    LOG_QUERY_LOCAL_ROOT,
    LOG_QUERY_MAX_LIMIT_BYTES,
    LOG_QUERY_MAX_TAIL_LINES,
)
from .kubernetes_routes import router as kubernetes_router
from .platform_routes import router as platform_router
from .platform_services import GITHUB_ACTIONS_SYNC_KEYS, Generator, PLATFORM_SECRET_KEYS


app = FastAPI(
    title="Dev Infra Broker",
    version="0.1.0",
    description=(
        "Internal broker for k3s deployment automation. "
        "Secret values remain internal and are never returned to callers."
    ),
)


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
                "GET /v1/kubernetes/namespaces/<namespace>/pods/<pod>",
                "GET /v1/kubernetes/namespaces/<namespace>/deployments/<name>",
                "GET /v1/kubernetes/namespaces/<namespace>/statefulsets/<name>",
                "GET /v1/kubernetes/namespaces/<namespace>/jobs",
                "GET /v1/kubernetes/namespaces/<namespace>/jobs/<name>",
                "GET /v1/kubernetes/namespaces/<namespace>/deployments/<name>/pods",
                "GET /v1/kubernetes/namespaces/<namespace>/events",
                "GET /v1/kubernetes/namespaces/<namespace>/dagster/runs/<runId>",
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
            "enabled": True,
            "mount": "k3s-kv",
            "path": "platform",
            "auth": "kubernetes",
            "role": "dev-infra-broker-platform-reader",
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


app.include_router(platform_router)
app.include_router(kubernetes_router)
