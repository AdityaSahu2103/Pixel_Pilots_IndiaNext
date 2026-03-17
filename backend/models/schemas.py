"""
CyberShield AI - Pydantic Data Models
All request/response schemas for the multi-agent pipeline.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ─── Enums ──────────────────────────────────────────────

class SourceType(str, Enum):
    """Type of input source being analyzed."""
    EMAIL = "email"
    URL = "url"
    TEXT = "text"
    FILE = "file"


class ThreatType(str, Enum):
    """Categories of cyber threats detected."""
    PHISHING = "phishing"
    MALICIOUS_URL = "malicious_url"
    DEEPFAKE = "deepfake"
    PROMPT_INJECTION = "prompt_injection"
    ANOMALY = "anomaly"
    AI_GENERATED = "ai_generated"


class SeverityLevel(str, Enum):
    """Threat severity classification."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"


class BreadcrumbSeverity(str, Enum):
    """Visual severity for breadcrumb highlighting."""
    RED = "red"
    ORANGE = "orange"
    YELLOW = "yellow"
    GREEN = "green"


# ─── Request Models ─────────────────────────────────────

class ScanRequest(BaseModel):
    """Main input schema for threat scanning."""
    source_type: SourceType
    content: str = Field(..., description="Raw content to analyze (text, email body, URL, etc.)")
    metadata: Optional[dict] = Field(default=None, description="Additional metadata (email headers, file info, etc.)")
    enable_adversarial: bool = Field(default=False, description="Run adversarial robustness testing")


class EmailScanRequest(BaseModel):
    """Email-specific scan request."""
    raw_email: str = Field(..., description="Raw email content (.eml format or plain text)")
    sender: Optional[str] = None
    subject: Optional[str] = None


class URLScanRequest(BaseModel):
    """URL-specific scan request."""
    url: str = Field(..., description="URL to scan")
    follow_redirects: bool = Field(default=True)


class TextScanRequest(BaseModel):
    """Text/message scan request."""
    text: str = Field(..., description="Text content to analyze")
    context: Optional[str] = Field(default=None, description="Context about where this text came from")


# ─── Extracted Content ──────────────────────────────────

class ExtractedContent(BaseModel):
    """Output from the content extraction agent."""
    source_type: SourceType
    plain_text: str = ""
    html_content: Optional[str] = None
    urls: list[str] = Field(default_factory=list)
    sender: Optional[str] = None
    subject: Optional[str] = None
    headers: Optional[dict] = None
    attachments: list[dict] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)


# ─── Detection Results ──────────────────────────────────

class EvidenceItem(BaseModel):
    """Single piece of evidence supporting a detection."""
    indicator: str = Field(..., description="What was found")
    description: str = Field(..., description="Why it's suspicious")
    severity: BreadcrumbSeverity = BreadcrumbSeverity.YELLOW
    position: Optional[dict] = Field(default=None, description="Position in original content (start, end)")


class ThreatDetection(BaseModel):
    """Result from an individual detection agent."""
    threat_type: ThreatType
    detected: bool = False
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    severity: SeverityLevel = SeverityLevel.SAFE
    evidence: list[EvidenceItem] = Field(default_factory=list)
    raw_scores: dict = Field(default_factory=dict, description="Raw API/model scores")
    agent_name: str = ""
    processing_time_ms: float = 0.0


class CrossValidationResult(BaseModel):
    """Result from the cross-validation agent."""
    original_detections: list[ThreatDetection]
    validated_detections: list[ThreatDetection]
    false_positives_reduced: int = 0
    consensus_score: float = 0.0
    validation_notes: list[str] = Field(default_factory=list)


# ─── Risk Scoring ───────────────────────────────────────

class RiskBreakdown(BaseModel):
    """Risk score breakdown by threat category."""
    threat_type: ThreatType
    score: float = Field(default=0.0, ge=0.0, le=100.0)
    weight: float = Field(default=1.0, description="Weight in composite score")


class RiskScore(BaseModel):
    """Composite risk assessment."""
    overall_score: float = Field(default=0.0, ge=0.0, le=100.0)
    severity: SeverityLevel = SeverityLevel.SAFE
    breakdown: list[RiskBreakdown] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


# ─── Breadcrumbs & Explainability ───────────────────────

class Breadcrumb(BaseModel):
    """Visual breadcrumb for evidence highlighting."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    content_snippet: str = Field(..., description="Relevant text/content snippet")
    threat_type: ThreatType
    severity: BreadcrumbSeverity
    description: str = ""
    position: Optional[dict] = None
    highlight_color: str = Field(default="#FF0000", description="Hex color for UI highlighting")


class ExplainerResult(BaseModel):
    """LLM-generated explanation of the scan results."""
    summary: str = Field(..., description="Human-readable threat summary")
    reasoning_chain: list[str] = Field(default_factory=list, description="Step-by-step reasoning")
    evidence_citations: list[str] = Field(default_factory=list, description="Evidence referenced")
    confidence_justification: str = ""
    recommended_actions: list[str] = Field(default_factory=list)
    threat_context: Optional[str] = Field(default=None, description="Real-world context from threat intel")
    llm_risk_score: Optional[float] = Field(default=None, description="0-100 risk score generated by LLM")
    llm_threat_scores: Optional[dict[str, float]] = Field(default=None, description="0.0-1.0 confidence scores by threat type")


# ─── Adversarial Testing ────────────────────────────────

class MutationResult(BaseModel):
    """Result of a single mutation test."""
    mutation_type: str
    mutated_input: str
    original_detected: bool
    mutated_detected: bool
    evasion_successful: bool = False


class AdversarialResult(BaseModel):
    """Complete adversarial testing results."""
    total_mutations: int = 0
    evasions_caught: int = 0
    evasions_missed: int = 0
    robustness_score: float = Field(default=0.0, ge=0.0, le=100.0)
    mutations: list[MutationResult] = Field(default_factory=list)


# ─── Main Response ──────────────────────────────────────

class ScanResponse(BaseModel):
    """Complete scan response returned to the client."""
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source_type: SourceType
    risk_score: RiskScore
    detections: list[ThreatDetection] = Field(default_factory=list)
    cross_validation: Optional[CrossValidationResult] = None
    explanation: Optional[ExplainerResult] = None
    breadcrumbs: list[Breadcrumb] = Field(default_factory=list)
    adversarial: Optional[AdversarialResult] = None
    processing_time_ms: float = 0.0
    attachments: list[dict] = Field(default_factory=list, description="Metadata of attachments scanned")


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "healthy"
    version: str = "1.0.0"
    agents: dict = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
