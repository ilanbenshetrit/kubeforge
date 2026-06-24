"""Health-check endpoints — used by Kubernetes liveness & readiness probes."""

from fastapi import APIRouter
from pydantic import BaseModel
from datetime import datetime
from kubeforge.config import settings

router = APIRouter()


class HealthResponse(BaseModel):
    status: str
    app: str
    version: str
    environment: str
    timestamp: str


@router.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """Kubernetes liveness probe — always returns 200 if the process is up."""
    return HealthResponse(
        status="healthy",
        app=settings.app_name,
        version=settings.version,
        environment=settings.environment,
        timestamp=datetime.utcnow().isoformat(),
    )


@router.get("/ready", tags=["System"])
async def readiness_check():
    """Kubernetes readiness probe — add real dependency checks here."""
    return {"status": "ready"}
