"""ThreatFuse AI — Health-check endpoint."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from app.core.config import settings

router = APIRouter(tags=["Health"])


class HealthResponse(BaseModel):
    """Health-check response schema."""

    status: str = "ok"
    version: str = settings.APP_VERSION
    app: str = settings.APP_NAME


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Returns application health status, version, and name.",
)
async def health_check() -> HealthResponse:
    """Return current application health."""
    return HealthResponse()
