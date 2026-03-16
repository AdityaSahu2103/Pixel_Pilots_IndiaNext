"""ThreatFuse AI — Structured Logging.

Uses Loguru for structured, colourful console + JSON logging.
"""

from __future__ import annotations

import sys

from loguru import logger

from app.core.config import settings


def setup_logging() -> None:
    """Configure application-wide logging with Loguru."""

    # Remove default handler
    logger.remove()

    # Console handler — human-readable
    logger.add(
        sys.stderr,
        level="DEBUG" if settings.DEBUG else "INFO",
        format=(
            "<green>{time:HH:mm:ss.SSS}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> — "
            "<level>{message}</level>"
        ),
        colorize=True,
        backtrace=True,
        diagnose=settings.DEBUG,
    )

    # JSON file handler — machine-readable
    logger.add(
        "logs/threatfuse.log",
        level="INFO",
        format="{message}",
        serialize=True,
        rotation="10 MB",
        retention="7 days",
        compression="zip",
        enqueue=True,
    )

    logger.info(
        "Logging initialised — app={app} version={version} debug={debug}",
        app=settings.APP_NAME,
        version=settings.APP_VERSION,
        debug=settings.DEBUG,
    )
