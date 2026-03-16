"""
CyberShield AI - Deepfake Analyzer Agent
Detects deepfake content using Reality Defender API.
"""
import time

import httpx

from backend.config import get_settings
from backend.models.schemas import (
    ThreatDetection, ThreatType, SeverityLevel, EvidenceItem,
    BreadcrumbSeverity, ExtractedContent
)


class DeepfakeAnalyzerAgent:
    """
    Deepfake detection using:
    1. Reality Defender API (primary — 50 scans available)
    2. Metadata heuristics (fallback)
    """

    AGENT_NAME = "deepfake_analyzer"

    REALITY_DEFENDER_BASE_URL = "https://api.realitydefender.com/v2"

    async def detect(self, extracted: ExtractedContent) -> ThreatDetection:
        """Analyze content for deepfake indicators."""
        start_time = time.time()
        evidence = []
        scores = {}

        # Check if content is media-related
        has_media = (
            any(att.get("content_type", "").startswith(("image/", "video/", "audio/"))
                for att in extracted.attachments)
            or extracted.metadata.get("content_type", "").startswith(("image/", "video/", "audio/"))
        )

        # 1. Reality Defender API scan (if media content)
        if has_media or extracted.metadata.get("media_url") or extracted.metadata.get("file_content"):
            rd_score, rd_evidence = await self._reality_defender_scan(extracted)
            scores["reality_defender"] = rd_score
            evidence.extend(rd_evidence)

        # 2. Metadata heuristics
        meta_score, meta_evidence = self._metadata_heuristics(extracted)
        scores["metadata_heuristics"] = meta_score
        evidence.extend(meta_evidence)

        # 3. Content-based text indicators (for AI-generated text)
        text_score, text_evidence = self._detect_ai_text_indicators(extracted.plain_text)
        scores["ai_text_indicators"] = text_score
        evidence.extend(text_evidence)

        # Composite confidence
        active_scores = [v for v in scores.values() if v > 0]
        confidence = max(active_scores) if active_scores else 0.0

        settings = get_settings()
        detected = confidence >= settings.deepfake_threshold

        severity = self._confidence_to_severity(confidence)
        processing_time = (time.time() - start_time) * 1000

        return ThreatDetection(
            threat_type=ThreatType.DEEPFAKE,
            detected=detected,
            confidence=round(confidence, 4),
            severity=severity,
            evidence=evidence,
            raw_scores=scores,
            agent_name=self.AGENT_NAME,
            processing_time_ms=round(processing_time, 2)
        )

    async def _reality_defender_scan(self, extracted: ExtractedContent) -> tuple[float, list[EvidenceItem]]:
        """Scan media using Reality Defender API."""
        settings = get_settings()
        if not settings.reality_defender_api_key:
            return 0.0, []

        try:
            headers = {
                "Authorization": f"Bearer {settings.reality_defender_api_key}",
                "Content-Type": "application/json"
            }

            # Determine media type and prepare request
            media_url = extracted.metadata.get("media_url", "")
            file_content = extracted.metadata.get("file_content", "")

            if media_url:
                payload = {"url": media_url}
            elif file_content:
                payload = {"file": file_content}
            elif extracted.attachments:
                # Use first media attachment info
                payload = {"metadata": extracted.attachments[0]}
            else:
                return 0.0, []

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.REALITY_DEFENDER_BASE_URL}/detect",
                    headers=headers,
                    json=payload
                )

                if response.status_code == 200:
                    data = response.json()

                    # Parse Reality Defender response
                    is_fake = data.get("is_fake", False)
                    fake_probability = data.get("fake_probability", 0.0)
                    detection_details = data.get("details", {})

                    evidence = []
                    if is_fake or fake_probability > 0.5:
                        evidence.append(EvidenceItem(
                            indicator="Reality Defender Detection",
                            description=f"Deepfake probability: {fake_probability:.1%}. {detection_details.get('reason', '')}",
                            severity=BreadcrumbSeverity.RED if fake_probability > 0.7 else BreadcrumbSeverity.ORANGE
                        ))

                    return fake_probability, evidence

                elif response.status_code == 429:
                    return 0.0, [EvidenceItem(
                        indicator="API Rate Limit",
                        description="Reality Defender scan limit reached (50 scans)",
                        severity=BreadcrumbSeverity.YELLOW
                    )]

            return 0.0, []
        except Exception as e:
            return 0.0, [EvidenceItem(
                indicator="API Error",
                description=f"Reality Defender API error: {str(e)[:100]}",
                severity=BreadcrumbSeverity.YELLOW
            )]

    def _metadata_heuristics(self, extracted: ExtractedContent) -> tuple[float, list[EvidenceItem]]:
        """Analyze metadata for deepfake indicators."""
        evidence = []
        score = 0.0

        for attachment in extracted.attachments:
            filename = attachment.get("filename", "").lower()
            content_type = attachment.get("content_type", "")

            # Flag suspicious file types
            if content_type.startswith(("video/", "audio/")):
                size = attachment.get("size", 0)

                # Unusually small video/audio files
                if content_type.startswith("video/") and 0 < size < 100_000:
                    score += 0.2
                    evidence.append(EvidenceItem(
                        indicator="Suspicious File Size",
                        description=f"Video file '{filename}' is unusually small ({size} bytes)",
                        severity=BreadcrumbSeverity.YELLOW
                    ))

                # Check for known deepfake tool artifacts in filename
                deepfake_tools = ["faceswap", "deepfake", "fake", "generated", "synthetic"]
                if any(tool in filename for tool in deepfake_tools):
                    score += 0.4
                    evidence.append(EvidenceItem(
                        indicator="Suspicious Filename",
                        description=f"Filename '{filename}' contains deepfake-related keywords",
                        severity=BreadcrumbSeverity.ORANGE
                    ))

        return min(score, 0.8), evidence

    def _detect_ai_text_indicators(self, text: str) -> tuple[float, list[EvidenceItem]]:
        """Detect indicators of AI-generated text content."""
        if not text or len(text) < 50:
            return 0.0, []

        evidence = []
        score = 0.0

        # Check for unnaturally perfect grammar and structure patterns
        ai_indicators = [
            "as an ai", "as a language model", "i cannot", "i'm unable to",
            "here's a", "here is a", "certainly!", "of course!",
            "i'd be happy to", "it's important to note",
            "in conclusion", "furthermore", "consequently",
        ]

        text_lower = text.lower()
        found = [ind for ind in ai_indicators if ind in text_lower]

        if len(found) >= 3:
            score = 0.5
            evidence.append(EvidenceItem(
                indicator="AI-Generated Text Patterns",
                description=f"Text contains {len(found)} AI-typical phrases: {', '.join(found[:3])}",
                severity=BreadcrumbSeverity.ORANGE
            ))
        elif len(found) >= 1:
            score = 0.2
            evidence.append(EvidenceItem(
                indicator="Possible AI Text Patterns",
                description=f"Text contains AI-typical phrase(s): {', '.join(found[:2])}",
                severity=BreadcrumbSeverity.YELLOW
            ))

        return score, evidence

    def _confidence_to_severity(self, confidence: float) -> SeverityLevel:
        if confidence >= 0.8:
            return SeverityLevel.CRITICAL
        elif confidence >= 0.6:
            return SeverityLevel.HIGH
        elif confidence >= 0.4:
            return SeverityLevel.MEDIUM
        elif confidence >= 0.2:
            return SeverityLevel.LOW
        return SeverityLevel.SAFE
