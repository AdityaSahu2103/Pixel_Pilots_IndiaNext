"""ThreatFuse AI — Shared Pydantic Models.

These types are used across backend agents and API responses.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


# ── Enums ────────────────────────────────────────────────────────


class ThreatType(str, Enum):
    """Supported threat categories."""

    PHISHING = "phishing"
    MALICIOUS_URL = "malicious_url"
    PROMPT_INJECTION = "prompt_injection"
    DEEPFAKE = "deepfake"
    ANOMALY = "anomaly"
    UNKNOWN = "unknown"


class MitigationAction(str, Enum):
    """Automated mitigation actions."""

    QUARANTINE = "QUARANTINE"
    REVIEW = "REVIEW"
    MONITOR = "MONITOR"


class SeverityLevel(str, Enum):
    """Threat severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ── Input / Output Schemas ───────────────────────────────────────


class ThreatInput(BaseModel):
    """Input payload for threat analysis."""

    input: str = Field(..., min_length=1, description="Raw threat content to analyze")
    input_type: ThreatType = Field(
        default=ThreatType.UNKNOWN,
        description="Type hint for the input; auto-detected if UNKNOWN",
    )


class Breadcrumb(BaseModel):
    """Single step in the threat-detection timeline."""

    timestamp: datetime = Field(default_factory=datetime.utcnow)
    agent: str = Field(..., description="Agent that produced this breadcrumb")
    event: str = Field(..., description="What was detected / analysed")
    detail: Optional[str] = None


class EvidenceHighlight(BaseModel):
    """A highlighted piece of suspicious content."""

    text: str
    reason: str
    confidence: float = Field(ge=0, le=100)


class AnalysisResult(BaseModel):
    """Full analysis response returned to the dashboard."""

    id: str = Field(..., description="Unique analysis ID")
    input_type: ThreatType
    risk_score: float = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=100)
    severity: SeverityLevel
    breadcrumbs: List[Breadcrumb] = []
    evidence: List[EvidenceHighlight] = []
    explanation: str = ""
    action: MitigationAction
    recommended_steps: List[str] = []
    analysed_at: datetime = Field(default_factory=datetime.utcnow)
