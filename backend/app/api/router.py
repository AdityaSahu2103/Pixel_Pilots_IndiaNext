"""ThreatFuse AI — Base API Router.

Mounts all endpoint sub-routers under the API prefix.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.endpoints import health

api_router = APIRouter()

# ── Mount sub-routers ────────────────────────────────────────────
api_router.include_router(health.router)
