"""
CyberShield AI - Cross-Validation Agent
Reduces false positives through multi-signal consensus.
"""
from backend.config import get_settings
from backend.models.schemas import (
    ThreatDetection, CrossValidationResult, SeverityLevel
)


class CrossValidatorAgent:
    """
    Validates detections by checking multi-agent consensus.
    Reduces false positives and adjusts confidence scores.
    """

    AGENT_NAME = "cross_validator"

    def validate(self, detections: list[ThreatDetection]) -> CrossValidationResult:
        """
        Cross-validate all detection results.
        - If only 1 agent flags and confidence < threshold → reduce
        - If multiple agents agree → boost confidence
        - Track false positive reductions
        """
        settings = get_settings()
        validated = []
        fp_reduced = 0
        notes = []

        # Count how many agents flagged threats
        flagged = [d for d in detections if d.detected]
        unflagged = [d for d in detections if not d.detected]

        for detection in detections:
            adjusted = detection.model_copy()

            if detection.detected:
                # Check consensus with other agents
                other_flagged = [d for d in flagged if d.threat_type != detection.threat_type]

                if len(flagged) == 1 and detection.confidence < 0.7:
                    # Single agent, moderate confidence → reduce
                    adjusted.confidence = detection.confidence * settings.false_positive_reduction_weight
                    if adjusted.confidence < 0.4:
                        adjusted.detected = False
                        adjusted.severity = SeverityLevel.LOW
                        fp_reduced += 1
                        notes.append(
                            f"{detection.threat_type.value}: Reduced (single-agent, low confidence)"
                        )
                    else:
                        notes.append(
                            f"{detection.threat_type.value}: Confidence adjusted down (single-agent)"
                        )

                elif len(flagged) >= 3:
                    # Strong consensus → boost
                    adjusted.confidence = min(detection.confidence * 1.15, 1.0)
                    notes.append(
                        f"{detection.threat_type.value}: Boosted (multi-agent consensus: {len(flagged)} agents)"
                    )

                elif len(flagged) >= 2:
                    # Moderate consensus
                    notes.append(
                        f"{detection.threat_type.value}: Confirmed ({len(flagged)} agents agree)"
                    )

            validated.append(adjusted)

        # Calculate consensus score
        if detections:
            agreement = len(flagged) / len(detections)
            consensus = agreement if len(flagged) <= len(detections) / 2 else (1 - agreement) + 0.5
        else:
            consensus = 0.0

        return CrossValidationResult(
            original_detections=detections,
            validated_detections=validated,
            false_positives_reduced=fp_reduced,
            consensus_score=round(consensus, 3),
            validation_notes=notes
        )
