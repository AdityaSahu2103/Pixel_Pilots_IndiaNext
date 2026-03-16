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
    BreadcrumbSeverity, ExtractedContent, SourceType
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
        
        n_samples = 300
        
        # 1. Normal Text (60% of data)
        normal_text = np.column_stack([
            rng.normal(500, 200, int(n_samples * 0.6)),    # text_length
            rng.poisson(2, int(n_samples * 0.6)),           # url_count
            rng.normal(0.05, 0.02, int(n_samples * 0.6)),   # special_char_ratio
            rng.normal(0.05, 0.03, int(n_samples * 0.6)),   # caps_ratio
            rng.normal(4.0, 0.5, int(n_samples * 0.6)),     # entropy
            rng.normal(5.0, 1.0, int(n_samples * 0.6)),     # avg_word_length
        ])
        
        # 2. URLs (20% of data - typical web domains and paths)
        urls = np.column_stack([
            rng.normal(35, 15, int(n_samples * 0.2)),       # text_length
            rng.poisson(1, int(n_samples * 0.2)),           # url_count (usually 1)
            rng.normal(0.15, 0.05, int(n_samples * 0.2)),   # special_char_ratio
            rng.normal(0.0, 0.02, int(n_samples * 0.2)),    # caps_ratio (mostly lowercase)
            rng.normal(3.5, 0.5, int(n_samples * 0.2)),     # entropy
            rng.normal(15.0, 5.0, int(n_samples * 0.2)),    # avg_word_length
        ])
        
        # 3. Short Messages (20% of data)
        short_msgs = np.column_stack([
            rng.normal(50, 20, int(n_samples * 0.2)),       # text_length
            rng.poisson(0, int(n_samples * 0.2)),           # url_count
            rng.normal(0.05, 0.03, int(n_samples * 0.2)),   # special_char_ratio
            rng.normal(0.10, 0.05, int(n_samples * 0.2)),   # caps_ratio
            rng.normal(3.8, 0.5, int(n_samples * 0.2)),     # entropy
            rng.normal(4.5, 1.0, int(n_samples * 0.2)),     # avg_word_length
        ])
        
        normal_data = np.vstack([normal_text, urls, short_msgs])
        # Force non-negative where impossible
        normal_data = np.clip(normal_data, a_min=0, a_max=None)
        
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

        is_url_scan = getattr(extracted, "source_type", None) == SourceType.URL
        
        # Run IsolationForest
        feature_array = np.array([features])
        anomaly_score = -self.model.score_samples(feature_array)[0]
        
        # Normalize to 0-1 range (typical scores are -0.5 to 0.5)
        # The higher the value, the more anomalous. Need to increase threshold slightly 
        # to avoid false positives on simple URLs
        if is_url_scan:
            # Web pages have highly variable structure naturally
            confidence = min(max((anomaly_score - 0.55) / 0.35, 0.0), 1.0)
        else:
            confidence = min(max((anomaly_score - 0.45) / 0.25, 0.0), 1.0)
            
        scores["isolation_forest"] = round(float(anomaly_score), 4)

        # Determine if it's primarily a URL/short text to adjust evidence thresholds
        is_mostly_url = (features[0] < 120 and len(extracted.urls) >= 1 and features[5] > 8)
        
        # Add evidence for anomalous features
        high_special_char_threshold = 0.25 if (is_mostly_url or is_url_scan) else 0.15
        if features[2] > high_special_char_threshold:
            evidence.append(EvidenceItem(
                indicator="High Special Character Ratio",
                description=f"Special character ratio: {features[2]:.1%} (normal: < {high_special_char_threshold:.0%})",
                severity=BreadcrumbSeverity.ORANGE
            ))

        high_caps_threshold = 0.5 if is_url_scan else 0.4
        if features[3] > high_caps_threshold:  # High caps ratio
            evidence.append(EvidenceItem(
                indicator="Excessive Capitalization",
                description=f"Caps ratio: {features[3]:.1%} (normal: < {high_caps_threshold:.0%})",
                severity=BreadcrumbSeverity.YELLOW
            ))

        actual_url_count = len(extracted.urls)
        many_urls_threshold = 50 if is_url_scan else 5
        if actual_url_count > many_urls_threshold:  # Many URLs
            evidence.append(EvidenceItem(
                indicator="Unusual URL Count",
                description=f"Contains {actual_url_count} URLs (normal: < {many_urls_threshold})",
                severity=BreadcrumbSeverity.ORANGE
            ))

        if confidence > 0.6:
            evidence.append(EvidenceItem(
                indicator="Statistical Anomaly",
                description=f"Content deviates significantly from normal patterns (anomaly score: {anomaly_score:.3f})",
                severity=BreadcrumbSeverity.RED if confidence > 0.8 else BreadcrumbSeverity.ORANGE
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
        if getattr(extracted, "source_type", None) == SourceType.URL:
            # Webpages naturally have many links; normalize it down so the ML model doesn't flag it as anomalous
            url_count = min(url_count / 20.0, 2.0)

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
