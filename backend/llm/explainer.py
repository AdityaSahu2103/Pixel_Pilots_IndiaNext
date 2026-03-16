"""
CyberShield AI - LLM Explainer Agent
Generates human-readable threat explanations using Groq LLM.
"""
import json
import re
from backend.config import get_settings
from backend.models.schemas import (
    ThreatDetection, ExplainerResult, RiskScore
)


class ExplainerAgent:
    """
    Uses Groq LLM (llama-3.3-70b-versatile) to generate:
    - Human-readable threat summaries
    - Step-by-step reasoning chains
    - Evidence citations
    - Actionable recommendations
    """

    AGENT_NAME = "llm_explainer"

    async def explain(
        self,
        detections: list[ThreatDetection],
        risk_score: RiskScore,
        context: str = "",
        original_content: str = ""
    ) -> ExplainerResult:
        """Generate LLM-powered explanation of scan results."""
        settings = get_settings()

        if not settings.groq_api_key:
            return self._fallback_explanation(detections, risk_score)

        try:
            from groq import AsyncGroq
            client = AsyncGroq(api_key=settings.groq_api_key)

            prompt = self._build_prompt(detections, risk_score, context, original_content)

            response = await client.chat.completions.create(
                model=settings.groq_model,
                messages=[
                    {"role": "system", "content": self._system_prompt()},
                    {"role": "user", "content": prompt}
                ],
                temperature=settings.groq_temperature,
                max_tokens=settings.groq_max_tokens
            )

            print(f"RAW GROK: {response.choices[0].message.content}")

            return self._parse_response(
                response.choices[0].message.content,
                detections, risk_score
            )

        except Exception as e:
            result = self._fallback_explanation(detections, risk_score)
            result.confidence_justification += f" (LLM error: {str(e)[:50]})"
            return result

    def _system_prompt(self) -> str:
        return (
            "You are CyberShield AI's Master Threat Analyst. Your job is to independently evaluate cybersecurity threats. "
            "You will be given the 'Original Content' (a URL, email, or text) and some raw 'Evidence' extracted by simple scanners.\n\n"
            "CRITICAL RULES FOR SCORING:\n"
            "1. You MUST evaluate the 'Original Content' on your own. DO NOT blindly trust the 'Evidence'. "
            "The simple scanners are notorious for False Positives. For example, they might flag a Safe URL (like https://www.amazon.com or https://www.google.com) as an 'Anomaly'. "
            "If the Original Content is a safe, widely known domain, or a normal benign message, you MUST return a score of 0, completely ignoring the false-positive evidence.\n"
            "2. Only give high 'phishing' or 'malicious_url' scores if the URL is clearly typosquatting (e.g. amazon-security-update.com) or the text is actually a social engineering attempt.\n\n"
            "Respond strictly in this JSON format:\n"
            "{\n"
            '  "summary": "2-3 sentence human-readable threat summary. State clearly if this is safe or a threat.",\n'
            '  "reasoning_chain": ["step 1...", "step 2..."],\n'
            '  "evidence_citations": ["relevant evidence..."],\n'
            '  "confidence_justification": "Why we are this confident",\n'
            '  "recommended_actions": ["action 1...", "action 2..."],\n'
            '  "llm_risk_score": 0,\n'
            '  "llm_threat_scores": {"phishing": 0.0, "malicious_url": 0.0, "deepfake": 0.0, "prompt_injection": 0.0, "anomaly": 0.0, "ai_generated": 0.0}\n'
            "}\n"
            "Provide the final, definitive exact scoring. 'llm_risk_score' must be an integer from 0-100 representing the overall risk. 'llm_threat_scores' must be float 0.0-1.0."
        )

    def _build_prompt(
        self, detections: list[ThreatDetection], risk_score: RiskScore,
        context: str, original_content: str
    ) -> str:
        parts = ["## Raw Evidence Collected by Agents (WARNING: May contain false positives - evaluate independently):"]
        
        for d in detections:
            if d.evidence:
                parts.append(f"\n### Threat Category: {d.threat_type.value}")
                # Limit to 5 evidence items to prevent LLM token rate limits (429 errors)
                limited_evidence = d.evidence[:5]
                for ev in limited_evidence:
                    parts.append(f"  - {ev.indicator}: {ev.description}")
                if len(d.evidence) > 5:
                    parts.append(f"  - ... and {len(d.evidence) - 5} more items.")

        if context:
            parts.append(f"\n## Threat Intelligence Context:\n{context}")

        if original_content:
            parts.append(f"\n## Original Content (Evaluate this directly!):\n{original_content[:2000]}")

        return "\n".join(parts)

    def _parse_response(
        self, response_text: str, detections: list[ThreatDetection],
        risk_score: RiskScore
    ) -> ExplainerResult:
        """Parse LLM JSON response into ExplainerResult."""
        try:
            text = response_text.strip()
            if "```" in text:
                m = re.search(r'```(?:json)?\s*(.*?)```', text, re.DOTALL)
                text = m.group(1).strip() if m else text

            data = json.loads(text)
            
            # Ensure float parsing for threat scores
            threat_scores = {}
            if "llm_threat_scores" in data and isinstance(data["llm_threat_scores"], dict):
                for k, v in data["llm_threat_scores"].items():
                    try:
                        threat_scores[k] = float(v)
                    except (ValueError, TypeError):
                        pass

            risk_score_val = None
            if "llm_risk_score" in data:
                try:
                    risk_score_val = float(data["llm_risk_score"])
                except (ValueError, TypeError):
                    pass

            return ExplainerResult(
                summary=data.get("summary", "Threat analysis complete."),
                reasoning_chain=data.get("reasoning_chain", []),
                evidence_citations=data.get("evidence_citations", []),
                confidence_justification=data.get("confidence_justification", ""),
                recommended_actions=data.get("recommended_actions", []),
                llm_risk_score=risk_score_val,
                llm_threat_scores=threat_scores if threat_scores else None
            )
        except (json.JSONDecodeError, Exception) as e:
            fallback = self._fallback_explanation(detections, risk_score)
            fallback.confidence_justification += f" (LLM Parse Error: {str(e)[:50]})"
            return fallback

    def _fallback_explanation(
        self, detections: list[ThreatDetection], risk_score: RiskScore
    ) -> ExplainerResult:
        """Generate explanation without LLM."""
        detected = [d for d in detections if d.detected]

        if not detected:
            return ExplainerResult(
                summary="No threats detected. The analyzed content appears safe.",
                reasoning_chain=["All detection agents returned negative results."],
                evidence_citations=[],
                confidence_justification="All agents agree the content is safe.",
                recommended_actions=["No action required. Content appears safe."]
            )

        threat_names = [d.threat_type.value.replace("_", " ") for d in detected]
        summary = (
            f"Detected {len(detected)} potential threat(s): {', '.join(threat_names)}. "
            f"Overall risk score: {risk_score.overall_score}/100 ({risk_score.severity.value})."
        )

        reasoning = []
        citations = []
        for d in detected:
            reasoning.append(
                f"{d.threat_type.value}: Confidence {d.confidence:.0%} with {len(d.evidence)} evidence items"
            )
            for ev in d.evidence:
                citations.append(f"[{d.threat_type.value}] {ev.indicator}: {ev.description}")

        actions = self._generate_actions(detected)

        return ExplainerResult(
            summary=summary,
            reasoning_chain=reasoning,
            evidence_citations=citations,
            confidence_justification=f"Based on {len(detected)} agent detections with cross-validation.",
            recommended_actions=actions
        )

    def _generate_actions(self, detected: list[ThreatDetection]) -> list[str]:
        """Generate recommended actions based on threat types."""
        actions = []
        threat_types = {d.threat_type.value for d in detected}

        if "phishing" in threat_types:
            actions.extend([
                "Do NOT click any links in this email",
                "Report this email as phishing to your IT department",
                "Verify the sender through an independent channel"
            ])
        if "malicious_url" in threat_types:
            actions.extend([
                "Do NOT visit the flagged URL(s)",
                "Block the domain in your firewall/proxy",
                "Scan any devices that may have accessed the URL"
            ])
        if "deepfake" in threat_types:
            actions.extend([
                "Verify the media source through independent channels",
                "Do not trust audio/video without verification",
                "Report to platform abuse team if applicable"
            ])
        if "prompt_injection" in threat_types:
            actions.extend([
                "Do NOT process this input through AI/LLM systems",
                "Sanitize and filter the input before any processing",
                "Review and strengthen input validation"
            ])
        if "anomaly" in threat_types:
            actions.extend([
                "Review recent account activity for unauthorized access",
                "Enable MFA if not already active",
                "Temporarily restrict account permissions"
            ])

        return actions if actions else ["Monitor the situation and review periodically."]
