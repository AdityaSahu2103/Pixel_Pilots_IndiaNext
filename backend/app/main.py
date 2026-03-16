"""ThreatFuse AI — FastAPI Application Entry Point."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from app.api.router import api_router
from app.core.config import settings
from app.core.logging import setup_logging


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan — startup & shutdown hooks."""
    setup_logging()
    logger.info("🚀 ThreatFuse AI starting up …")
    yield
    logger.info("🛑 ThreatFuse AI shutting down …")


def create_app() -> FastAPI:
    """Application factory — builds and configures the FastAPI instance."""

    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="Agentic Cybersecurity Platform — detect, explain & mitigate threats",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # ── CORS Middleware ──────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Routers ──────────────────────────────────────────────────
    app.include_router(api_router, prefix=settings.API_PREFIX)

    # Also mount health at root for Docker/k8s probes
    from app.api.endpoints.health import router as health_router

    app.include_router(health_router)

    return app


app = create_app()
