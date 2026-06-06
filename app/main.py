from fastapi import FastAPI

from .capabilities import capabilities_payload
from .kubernetes_routes import router as kubernetes_router
from .platform_routes import router as platform_router
from .workload_routes import router as workload_router


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
    return capabilities_payload()


app.include_router(platform_router)
app.include_router(kubernetes_router)
app.include_router(workload_router)
