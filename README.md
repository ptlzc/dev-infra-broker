# dev-infra-broker

Internal dev-infra automation broker for the `txyun` k3s platform.

This version is intentionally conservative:

- exposes `/healthz`
- exposes `/v1/capabilities`
- exposes OpenAPI through FastAPI at `/openapi.json`
- exposes `/v1/platform/secrets/status` to report whether required platform secret keys exist
- defines runtime secret and GitHub Actions secret sync endpoints
- returns `501` for write-capable endpoints until authentication, authorization, auditing, and backend credentials are implemented

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

## Local Run

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8080
```
