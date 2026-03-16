"""
CyberShield AI — Multi-Agent Cyber Defense Platform
FastAPI Application Entry Point

Detects, analyzes, and explains emerging cyber threats using
a multi-agent AI/ML pipeline with explainable AI.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config import get_settings
from backend.routers import health, analyze, reports, live_sync

settings = get_settings()

app = FastAPI(
    title="CyberShield AI",
    description=(
        "Multi-Agent Cyber Defense Platform — Detects phishing, malicious URLs, "
        "deepfakes, prompt injection, and anomalous behavior with explainable AI."
    ),
    version=settings.app_version,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(health.router)
app.include_router(analyze.router)
app.include_router(reports.router)
app.include_router(live_sync.router)


@app.get("/")
async def root():
    """Root endpoint — API info."""
    return {
        "name": "CyberShield AI",
        "version": settings.app_version,
        "description": "Multi-Agent Cyber Defense Platform",
        "docs": "/docs",
        "health": "/api/health",
        "endpoints": {
            "analyze": "POST /api/analyze",
            "analyze_email": "POST /api/analyze/email",
            "analyze_url": "POST /api/analyze/url",
            "analyze_text": "POST /api/analyze/text",
            "health": "GET /api/health",
            "reports": "GET /api/reports",
            "report_detail": "GET /api/reports/{scan_id}",
            "adversarial_test": "POST /api/reports/{scan_id}/adversarial",
        }
    }


@app.on_event("startup")
async def startup_event():
    """Initialize agents and verify configuration on startup."""
    print("=" * 60)
    print("  CyberShield AI — Starting Up")
    print("=" * 60)
    print(f"  Environment: {settings.app_env}")
    print(f"  VirusTotal API: {'✓' if settings.virustotal_api_key else '✗'}")
    print(f"  Google Safe Browsing: {'✓' if settings.google_safe_browsing_api_key else '✗'}")
    print(f"  Reality Defender: {'✓' if settings.reality_defender_api_key else '✗'}")
    print(f"  Groq LLM: {'✓' if settings.groq_api_key else '✗'}")
    print(f"  SERP API: {'✓' if settings.serp_api_key else '✗ (optional)'}")
    print("=" * 60)
