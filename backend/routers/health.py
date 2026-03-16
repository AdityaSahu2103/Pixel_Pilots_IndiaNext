"""
CyberShield AI - Health Check Router
"""
from datetime import datetime
from fastapi import APIRouter
from backend.models.schemas import HealthResponse
from backend.config import get_settings

router = APIRouter(prefix="/api", tags=["Health"])


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """System health check — returns agent status and config."""
    settings = get_settings()

    agents = {
        "content_extractor": "active",
        "phishing_detector": "active" if settings.google_safe_browsing_api_key else "degraded (no API key)",
        "url_scanner": "active" if settings.virustotal_api_key else "degraded (no API key)",
        "deepfake_analyzer": "active" if settings.reality_defender_api_key else "degraded (no API key)",
        "prompt_injection_detector": "active",
        "anomaly_detector": "active",
        "cross_validator": "active",
        "llm_explainer": "active" if settings.groq_api_key else "degraded (no API key)",
        "context_enricher": "active" if settings.serp_api_key else "degraded (optional)",
        "adversarial_tester": "active",
    }

    return HealthResponse(
        status="healthy",
        version=settings.app_version,
        agents=agents,
        timestamp=datetime.utcnow()
    )
