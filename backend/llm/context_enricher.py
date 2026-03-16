"""
CyberShield AI - Context Enricher
Enriches detection results with live threat intelligence via SERP API.
"""
import httpx
from backend.config import get_settings
from backend.models.schemas import ThreatDetection


# Curated threat intel context snippets
THREAT_CONTEXT_DB = {
    "phishing": (
        "Phishing attacks account for 36% of all data breaches (Verizon DBIR 2024). "
        "Modern phishing uses AI to generate highly convincing emails. Key indicators: "
        "spoofed domains, urgency language, mismatched sender addresses, and failed "
        "email authentication (SPF/DKIM/DMARC)."
    ),
    "malicious_url": (
        "Malicious URLs exploit browser and user trust. Common techniques include "
        "homograph attacks (lookalike characters), URL shortener abuse, domain "
        "squatting, and redirect chains to evade detection."
    ),
    "deepfake": (
        "Deepfake technology has advanced rapidly with tools like DALL-E, Midjourney, "
        "and open-source face-swap models. Detection remains challenging as generation "
        "quality improves. Key tells: metadata inconsistencies, audio-visual sync "
        "errors, and compression artifacts."
    ),
    "prompt_injection": (
        "Prompt injection is a critical vulnerability in LLM-powered apps. Attackers "
        "embed instructions in user inputs to override system prompts, extract "
        "training data, or manipulate outputs. OWASP lists it as the #1 LLM risk."
    ),
    "anomaly": (
        "Anomalous behavior detection uses statistical baselines to identify unusual "
        "patterns indicating insider threats, credential theft, or automated attacks. "
        "Key features: login timing, location, frequency, and content patterns."
    ),
}


class ContextEnricher:
    """Enriches threat detections with real-world context."""

    async def enrich(self, detections: list[ThreatDetection]) -> str:
        """
        Build enriched context string from curated knowledge + optional SERP API.
        """
        context_parts = []

        # Add curated context for detected threat types
        for detection in detections:
            if detection.detected:
                key = detection.threat_type.value
                if key in THREAT_CONTEXT_DB:
                    context_parts.append(
                        f"**{key.upper()} Context:** {THREAT_CONTEXT_DB[key]}"
                    )

        # Try live enrichment via SERP API
        live_context = await self._serp_search(detections)
        if live_context:
            context_parts.append(f"**Live Threat Intel:** {live_context}")

        return "\n\n".join(context_parts) if context_parts else ""

    async def _serp_search(self, detections: list[ThreatDetection]) -> str:
        """Fetch live threat intelligence via SERP API."""
        settings = get_settings()
        if not settings.serp_api_key:
            return ""

        detected_types = [d.threat_type.value for d in detections if d.detected]
        if not detected_types:
            return ""

        query = f"cybersecurity {' '.join(detected_types[:2])} threat 2024 2025"

        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                response = await client.get(
                    "https://serpapi.com/search",
                    params={
                        "q": query,
                        "api_key": settings.serp_api_key,
                        "engine": "google",
                        "num": 3
                    }
                )

                if response.status_code == 200:
                    data = response.json()
                    snippets = []
                    for result in data.get("organic_results", [])[:3]:
                        snippet = result.get("snippet", "")
                        if snippet:
                            snippets.append(snippet)
                    return " | ".join(snippets)

        except Exception:
            pass

        return ""
