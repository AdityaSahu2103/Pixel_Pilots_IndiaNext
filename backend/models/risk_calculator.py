"""
CyberShield AI - Risk Calculator
Computes composite risk scores from multiple agent detections.
"""
from backend.models.schemas import (
    ThreatDetection, RiskScore, RiskBreakdown, SeverityLevel, ThreatType
)


# Threat type weights for composite scoring
THREAT_WEIGHTS = {
    ThreatType.PHISHING: 1.0,
    ThreatType.MALICIOUS_URL: 0.9,
    ThreatType.DEEPFAKE: 0.85,
    ThreatType.PROMPT_INJECTION: 0.8,
    ThreatType.ANOMALY: 0.7,
    ThreatType.AI_GENERATED: 0.75,
}


def calculate_risk_score(detections: list[ThreatDetection]) -> RiskScore:
    """
    Calculate composite risk score from all agent detections.
    Uses weighted averaging with severity escalation.
    """
    if not detections:
        return RiskScore(
            overall_score=0.0,
            severity=SeverityLevel.SAFE,
            breakdown=[],
            confidence=0.0
        )

    breakdown = []
    weighted_sum = 0.0
    total_weight = 0.0
    max_confidence = 0.0

    for detection in detections:
        weight = THREAT_WEIGHTS.get(detection.threat_type, 0.5)
        score = detection.confidence * 100

        breakdown.append(RiskBreakdown(
            threat_type=detection.threat_type,
            score=score,
            weight=weight
        ))

        if detection.detected:
            weighted_sum += score * weight
            total_weight += weight

        max_confidence = max(max_confidence, detection.confidence)

    # Calculate overall score
    overall_score = weighted_sum / total_weight if total_weight > 0 else 0.0
    overall_score = min(overall_score, 100.0)

    # Determine severity level
    severity = _score_to_severity(overall_score)

    return RiskScore(
        overall_score=round(overall_score, 2),
        severity=severity,
        breakdown=breakdown,
        confidence=round(max_confidence, 3)
    )


def _score_to_severity(score: float) -> SeverityLevel:
    """Map a numeric score to severity level."""
    if score >= 80:
        return SeverityLevel.CRITICAL
    elif score >= 60:
        return SeverityLevel.HIGH
    elif score >= 40:
        return SeverityLevel.MEDIUM
    elif score >= 20:
        return SeverityLevel.LOW
    else:
        return SeverityLevel.SAFE
