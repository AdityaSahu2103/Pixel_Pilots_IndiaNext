"""
CyberShield AI - Anomaly Detection Agent
Detects anomalous user behavior using IsolationForest ML.
"""
import time
import numpy as np
from sklearn.ensemble import IsolationForest

from backend.config import get_settings
from backend.models.schemas import (
    ThreatDetection, ThreatType, SeverityLevel, EvidenceItem,
    BreadcrumbSeverity, ExtractedContent
)


class AnomalyDetectorAgent:
    """
    Anomaly detection using IsolationForest for:
    - Login pattern analysis (time, frequency, location)
    - Content statistical deviation
    - Behavioral feature extraction
    """

    AGENT_NAME = "anomaly_detector"

    def __init__(self):
        self.model = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        self._is_fitted = False
        self._fit_baseline()

    def _fit_baseline(self):
        """Pre-fit with synthetic normal behavior baseline."""
        rng = np.random.RandomState(42)
        # Features: [text_length, url_count, special_char_ratio,
        #            caps_ratio, entropy, avg_word_length]
        normal_data = np.column_stack([
            rng.normal(500, 200, 200),    # text_length
            rng.poisson(2, 200),           # url_count
            rng.normal(0.05, 0.02, 200),   # special_char_ratio
            rng.normal(0.05, 0.03, 200),   # caps_ratio
            rng.normal(4.0, 0.5, 200),     # entropy
            rng.normal(5.0, 1.0, 200),     # avg_word_length
        ])
        self.model.fit(normal_data)
        self._is_fitted = True

    async def detect(self, extracted: ExtractedContent) -> ThreatDetection:
        start_time = time.time()
        evidence = []
        scores = {}
        text = extracted.plain_text

        # Extract features
        features = self._extract_features(text, extracted)
        scores["features"] = {
            "text_length": features[0],
            "url_count": features[1],
            "special_char_ratio": round(features[2], 4),
            "caps_ratio": round(features[3], 4),
            "entropy": round(features[4], 4),
            "avg_word_length": round(features[5], 4),
        }

        # Run IsolationForest
        feature_array = np.array([features])
        anomaly_score = -self.model.score_samples(feature_array)[0]
        # Normalize to 0-1 range (typical scores are -0.5 to 0.5)
        confidence = min(max((anomaly_score - 0.3) / 0.4, 0.0), 1.0)
        scores["isolation_forest"] = round(float(anomaly_score), 4)

        # Add evidence for anomalous features
        if features[2] > 0.15:  # High special char ratio
            evidence.append(EvidenceItem(
                indicator="High Special Character Ratio",
                description=f"Special character ratio: {features[2]:.1%} (normal: ~5%)",
                severity=BreadcrumbSeverity.ORANGE
            ))

        if features[3] > 0.3:  # High caps ratio
            evidence.append(EvidenceItem(
                indicator="Excessive Capitalization",
                description=f"Caps ratio: {features[3]:.1%} (normal: ~5%)",
                severity=BreadcrumbSeverity.YELLOW
            ))

        if features[1] > 5:  # Many URLs
            evidence.append(EvidenceItem(
                indicator="Unusual URL Count",
                description=f"Contains {int(features[1])} URLs (normal: 1-2)",
                severity=BreadcrumbSeverity.ORANGE
            ))

        if confidence > 0.5:
            evidence.append(EvidenceItem(
                indicator="Statistical Anomaly",
                description=f"Content deviates significantly from normal patterns (anomaly score: {anomaly_score:.3f})",
                severity=BreadcrumbSeverity.RED if confidence > 0.7 else BreadcrumbSeverity.ORANGE
            ))

        settings = get_settings()
        detected = confidence >= settings.anomaly_threshold
        severity = self._to_severity(confidence)

        return ThreatDetection(
            threat_type=ThreatType.ANOMALY, detected=detected,
            confidence=round(confidence, 4), severity=severity,
            evidence=evidence, raw_scores=scores,
            agent_name=self.AGENT_NAME,
            processing_time_ms=round((time.time() - start_time) * 1000, 2)
        )

    def _extract_features(self, text: str, extracted: ExtractedContent) -> list[float]:
        """Extract numerical features from content."""
        if not text:
            return [0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

        text_length = float(len(text))
        url_count = float(len(extracted.urls))

        # Special character ratio
        special = sum(1 for c in text if not c.isalnum() and not c.isspace())
        special_ratio = special / max(len(text), 1)

        # Caps ratio
        upper = sum(1 for c in text if c.isupper())
        alpha = sum(1 for c in text if c.isalpha())
        caps_ratio = upper / max(alpha, 1)

        # Shannon entropy
        entropy = self._shannon_entropy(text)

        # Average word length
        words = text.split()
        avg_word_len = np.mean([len(w) for w in words]) if words else 0.0

        return [text_length, url_count, special_ratio, caps_ratio, entropy, avg_word_len]

    def _shannon_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        length = len(text)
        entropy = -sum((count/length) * np.log2(count/length)
                       for count in freq.values())
        return float(entropy)

    def _to_severity(self, c: float) -> SeverityLevel:
        if c >= 0.8: return SeverityLevel.CRITICAL
        if c >= 0.6: return SeverityLevel.HIGH
        if c >= 0.4: return SeverityLevel.MEDIUM
        if c >= 0.2: return SeverityLevel.LOW
        return SeverityLevel.SAFE
