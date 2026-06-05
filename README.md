# dev-infra-broker

Internal dev-infra automation broker for the `txyun` k3s platform.

This version is intentionally conservative:

- exposes `/healthz`
- exposes `/v1/capabilities`
- exposes OpenAPI through FastAPI at `/openapi.json`
- exposes `/v1/platform/secrets/status` to report whether required platform secret keys exist
- exposes Kubernetes pod discovery, workload status, events, ArgoCD application status, and bounded redacted pod log snapshots for non-system application namespaces
- syncs approved platform keys into GitHub Actions Repository secrets
- ensures generated runtime bootstrap secrets in Vault without returning secret values

The service must never return secret values. Runtime Vault paths, Vault tokens, GitHub credentials, and generated secret values are platform-internal implementation details.

## Platform Secret Source

The broker reads platform-level secret source keys from Vault KV v2 and returns only key presence status.

Default source:

```text
k3s-kv/platform
```

Expected keys:

- `REGISTRY_USERNAME`
- `REGISTRY_PASSWORD`
- `REGISTRY_URL`
- `REGISTRY_NAMESPACE`
- `GH_PAT`

Runtime Vault configuration:

- `VAULT_ADDR`
- `VAULT_KV_MOUNT`, default `k3s-kv`
- `VAULT_PLATFORM_SECRET_PATH`, default `platform`
- `VAULT_K8S_AUTH_MOUNT`, default `kubernetes`
- `VAULT_K8S_ROLE`, default `dev-infra-broker-platform-reader`

Do not configure long-lived Vault tokens in GitOps. In-cluster runtime should use Vault Kubernetes Auth with the broker ServiceAccount.

## GitHub Actions Secret Sync

Endpoint:

```text
POST /v1/github/repositories/{owner}/{repo}/actions-secrets/sync
```

Allowed target keys:

- `REGISTRY_USERNAME`
- `REGISTRY_PASSWORD`
- `REGISTRY_URL`
- `REGISTRY_NAMESPACE`

`GH_PAT` is used only by the broker to call GitHub's repository secrets API. It is never synced into a target repository.

Example request:

```json
{
  "cluster": "txyun",
  "secretSet": "platform",
  "keys": ["REGISTRY_USERNAME", "REGISTRY_PASSWORD"]
}
```

The response contains only key names.

## Kubernetes Diagnostics

All namespace-scoped Kubernetes diagnostics are limited to non-system application namespaces. The broker returns summarized status only and never returns Kubernetes Secret values.

### Pod Discovery

Endpoint:

```text
GET /v1/kubernetes/namespaces/{namespace}/pods
```

Supported query parameters:

- `labelSelector`
- `fieldSelector`
- `phase`

Each returned pod includes `podName`, `phase`, `restartCount`, `nodeName`, `ownerReferences`, `containerStatuses`, `initContainerStatuses`, timestamps, and labels.

Deployment pod shortcut:

```text
GET /v1/kubernetes/namespaces/{namespace}/deployments/{name}/pods
```

### Workload Status

Endpoints:

```text
GET /v1/kubernetes/namespaces/{namespace}/deployments/{name}
GET /v1/kubernetes/namespaces/{namespace}/statefulsets/{name}
```

Responses include desired, ready, available, updated, and current replica counts, `observedGeneration`, conditions, and related events.

### Events

Endpoint:

```text
GET /v1/kubernetes/namespaces/{namespace}/events
```

Supported query parameters:

- `involvedObjectKind`
- `involvedObjectName`
- `involvedObjectUid`

Use this for scheduler, image pull, and restart-loop diagnosis.

### Pod Log Query

Endpoint:

```text
GET /v1/kubernetes/namespaces/{namespace}/pods/{pod}/logs
```

Supported query parameters:

- `container`
- `previous`
- `tailLines`
- `sinceSeconds`
- `limitBytes`
- `timestamps`

Additional endpoints can resolve the latest pod before reading logs:

```text
GET /v1/kubernetes/namespaces/{namespace}/deployments/{name}/logs
GET /v1/kubernetes/namespaces/{namespace}/pods/logs?labelSelector={selector}
```

These responses include `resolvedPodName` and a `selection` object showing how the pod was selected. The broker returns a bounded snapshot only. Log queries are redacted with best-effort pattern masking and do not support streaming follow mode.

## ArgoCD Application Status

Endpoint:

```text
GET /v1/argocd/applications/{name}
```

Responses include `sync`, `health`, `operationState`, and `revision` from the ArgoCD `Application` status.

## Runtime Secret Ensure

Endpoint:

```text
POST /v1/runtime-secret-sets/ensure
```

The broker reads the existing Vault KV path, generates only missing generated keys, writes by KV v2 merge patch, and returns only key names.

Path convention:

```text
k3s-kv/projects/<namespace>/<serviceAccountName>/env
```

Example request:

```json
{
  "cluster": "txyun",
  "namespace": "example-api",
  "serviceAccountName": "example-api",
  "destinationSecretName": "example-api-env",
  "generated": {
    "SESSION_SECRET": {"generator": "random-base64", "bytes": 32}
  },
  "requiredExisting": ["OPENAI_API_KEY"]
}
```

Generated keys are idempotent: existing non-empty values are not overwritten, so a normal deploy does not rotate secrets.

## Local Run

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8080
```
