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
        """Scan media using the local Deepfake Microservice (port 8001)."""
        DEEPFAKE_MICROSERVICE_URL = "http://localhost:8001"

        try:
            # Determine media type and prepare request
            media_content = extracted.metadata.get("file_content")
            mime_type = extracted.metadata.get("content_type", "")
            filename = extracted.metadata.get("filename", "upload.unknown")

            # Fallback to checking attachments if metadata file_content is empty
            if not media_content and extracted.attachments:
                for att in extracted.attachments:
                    if att.get("content_type", "").startswith(("image/", "video/", "audio/")):
                        media_content = att.get("content")  # Assuming content bytes are here
                        mime_type = att.get("content_type", "")
                        filename = att.get("filename", "attachment.unknown")
                        break

            if not media_content:
                return 0.0, []

            # Routing logic based on mime type
            if mime_type.startswith("image/"):
                endpoint = f"{DEEPFAKE_MICROSERVICE_URL}/analyze/image"
            elif mime_type.startswith("audio/"):
                endpoint = f"{DEEPFAKE_MICROSERVICE_URL}/analyze/audio"
            elif mime_type.startswith("video/"):
                endpoint = f"{DEEPFAKE_MICROSERVICE_URL}/analyze/video"
            else:
                return 0.0, []

            async with httpx.AsyncClient(timeout=120.0) as client:
                files = {"file": (filename, media_content, mime_type)}
                response = await client.post(endpoint, files=files)

                if response.status_code == 200:
                    data = response.json()

                    # Parse Microservice Response
                    status_verdict = data.get("status", "AUTHENTIC")
                    score_0_100 = data.get("score", 0.0)
                    confidence_str = data.get("confidence", "LOW")
                    models = data.get("models", [])

                    fake_probability = score_0_100 / 100.0
                    evidence = []

                    if status_verdict in ["FAKE", "SUSPICIOUS"] or fake_probability > 0.5:
                        model_details = ", ".join([f"{m['name']}: {m['score']}%" for m in models[:2]])
                        evidence.append(EvidenceItem(
                            indicator=f"Deepfake Microservice Detection ({confidence_str} CONFIDENCE)",
                            description=f"Deepfake probability: {fake_probability:.1%}. Verdict: {status_verdict}. Models: {model_details}",
                            severity=BreadcrumbSeverity.RED if fake_probability > 0.7 else BreadcrumbSeverity.ORANGE
                        ))
                    else:
                        evidence.append(EvidenceItem(
                            indicator="Deepfake Microservice Scan (AUTHENTIC)",
                            description=f"Scanned by Reality Defender. Verdict: {status_verdict} ({fake_probability:.1%} probability).",
                            severity=BreadcrumbSeverity.GREEN
                        ))

                    return fake_probability, evidence

                elif response.status_code == 422:
                    error_detail = response.json().get("detail", "Unprocessable entity")
                    return 0.0, [EvidenceItem(
                        indicator="Deepfake Scan Inconclusive",
                        description=f"{error_detail} Reality Defender Free Tier requires visible faces or clear speech to evaluate AI manipulation.",
                        severity=BreadcrumbSeverity.YELLOW
                    )]
                else:
                    return 0.0, [EvidenceItem(
                        indicator="Microservice Error",
                        description=f"Deepfake service returned {response.status_code}: {response.text[:100]}",
                        severity=BreadcrumbSeverity.YELLOW
                    )]
        except Exception as e:
            return 0.0, [EvidenceItem(
                indicator="Microservice Connection Error",
                description=f"Could not reach Deepfake Microservice at port 8001: {str(e)[:100]}",
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
            score = 0.75
            evidence.append(EvidenceItem(
                indicator="AI-Generated Text Patterns",
                description=f"Text contains {len(found)} AI-typical phrases: {', '.join(found[:3])}",
                severity=BreadcrumbSeverity.RED
            ))
        elif len(found) >= 1:
            score = 0.45
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
