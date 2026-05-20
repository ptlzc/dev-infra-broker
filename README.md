# dev-infra-broker

Internal dev-infra automation broker for the `txyun` k3s platform.

This first version is intentionally read-only/skeleton mode:

- exposes `/healthz`
- exposes `/v1/capabilities`
- exposes OpenAPI through FastAPI at `/openapi.json`
- defines runtime secret and GitHub Actions secret sync endpoints
- returns `501` for write-capable endpoints until authentication, authorization, auditing, and backend credentials are implemented

The service must never return secret values. Runtime Vault paths, Vault tokens, GitHub credentials, and generated secret values are platform-internal implementation details.

## Local Run

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

