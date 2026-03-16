"""
CyberShield AI - Prompt Injection Detection Agent
Detects prompt injection attacks using pattern matching + LLM scoring.
"""
import re
import time
import json

from backend.config import get_settings
from backend.models.schemas import (
    ThreatDetection, ThreatType, SeverityLevel, EvidenceItem,
    BreadcrumbSeverity, ExtractedContent
)

# Known prompt injection patterns: (regex, score, label)
INJECTION_PATTERNS = [
    (r'ignore\s+(all\s+)?previous\s+(instructions?|prompts?|context)', 0.85, "Direct instruction override"),
    (r'forget\s+(all\s+)?previous', 0.80, "Memory wipe attempt"),
    (r'disregard\s+(all\s+)?previous', 0.80, "Instruction disregard"),
    (r'override\s+(all\s+)?previous', 0.80, "Override attempt"),
    (r'(show|reveal|print|output)\s+(me\s+)?(your|the)\s+(system\s+)?(prompt|instructions)', 0.75, "System prompt extraction"),
    (r'what\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions|rules)', 0.70, "System prompt query"),
    (r'repeat\s+(your\s+)?(initial|original|system)\s+(prompt|instructions)', 0.75, "Prompt repetition request"),
    (r'you\s+are\s+now\s+(DAN|jailbreak|unrestricted|evil)', 0.90, "DAN/Jailbreak attempt"),
    (r'pretend\s+(you\s+are|to\s+be)\s+(a|an)\s+(unrestricted|unfiltered|evil)', 0.85, "Role-play exploitation"),
    (r'act\s+as\s+(if\s+)?you\s+(have\s+)?no\s+(restrictions?|filters?|rules?)', 0.85, "Restriction bypass"),
    (r'enter\s+(developer|debug|admin|god)\s+mode', 0.80, "Mode switch attempt"),
    (r'```\s*system\s*\n', 0.70, "System block injection"),
    (r'\[SYSTEM\]', 0.75, "System tag injection"),
    (r'<\|system\|>', 0.80, "System delimiter injection"),
    (r'###\s*(system|instruction|admin)', 0.70, "Markdown system header"),
    (r'(respond|answer|reply)\s+(only\s+)?with\s+"', 0.60, "Output manipulation"),
    (r'base64\s*:\s*[A-Za-z0-9+/=]{20,}', 0.65, "Base64 encoded payload"),
    (r'step\s*1.*ignore.*step\s*2', 0.70, "Multi-step injection"),
]


class PromptInjectionAgent:
    """Prompt injection detection via patterns, structure, and LLM analysis."""

    AGENT_NAME = "prompt_injection_detector"

    async def detect(self, extracted: ExtractedContent) -> ThreatDetection:
        start_time = time.time()
        evidence = []
        scores = {}
        text = extracted.plain_text

        if not text:
            return ThreatDetection(
                threat_type=ThreatType.PROMPT_INJECTION, detected=False,
                confidence=0.0, severity=SeverityLevel.SAFE,
                agent_name=self.AGENT_NAME,
                processing_time_ms=(time.time() - start_time) * 1000
            )

        # 1. Pattern-based detection
        pattern_score, pattern_ev = self._pattern_detection(text)
        scores["pattern_detection"] = pattern_score
        evidence.extend(pattern_ev)

        # 2. Structural analysis
        struct_score, struct_ev = self._structural_analysis(text)
        scores["structural_analysis"] = struct_score
        evidence.extend(struct_ev)

        # 3. LLM semantic analysis if inconclusive
        if 0.2 <= pattern_score <= 0.7 or struct_score > 0.3:
            llm_score, llm_ev = await self._llm_analysis(text)
            scores["llm_analysis"] = llm_score
            evidence.extend(llm_ev)

        confidence = max(scores.values()) if scores else 0.0
        active = [v for v in scores.values() if v > 0.3]
        if len(active) >= 2:
            confidence = min(confidence * 1.15, 1.0)

        settings = get_settings()
        detected = confidence >= settings.prompt_injection_threshold
        severity = self._to_severity(confidence)

        return ThreatDetection(
            threat_type=ThreatType.PROMPT_INJECTION, detected=detected,
            confidence=round(confidence, 4), severity=severity,
            evidence=evidence, raw_scores=scores,
            agent_name=self.AGENT_NAME,
            processing_time_ms=round((time.time() - start_time) * 1000, 2)
        )

    def _pattern_detection(self, text: str) -> tuple[float, list[EvidenceItem]]:
        evidence = []
        max_score = 0.0
        for pattern, score, desc in INJECTION_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE | re.DOTALL)
            if matches:
                max_score = max(max_score, score)
                match_str = matches[0] if isinstance(matches[0], str) else str(matches[0])
                evidence.append(EvidenceItem(
                    indicator="Injection Pattern",
                    description=f"{desc}: '{match_str[:80]}'",
                    severity=BreadcrumbSeverity.RED if score > 0.7 else BreadcrumbSeverity.ORANGE
                ))
        return max_score, evidence

    def _structural_analysis(self, text: str) -> tuple[float, list[EvidenceItem]]:
        evidence = []
        score = 0.0

        # Role-switching markers
        role_switches = len(re.findall(r'\n\s*(user|assistant|system|human|ai)\s*:', text, re.I))
        if role_switches >= 2:
            score += 0.4
            evidence.append(EvidenceItem(
                indicator="Role-Switch Formatting",
                description=f"{role_switches} role-switch markers detected",
                severity=BreadcrumbSeverity.RED
            ))

        # Code blocks with system keywords
        if text.count("```") >= 2:
            blocks = re.findall(r'```.*?```', text, re.DOTALL)
            for block in blocks:
                if any(kw in block.lower() for kw in ["system", "instruction", "prompt"]):
                    score += 0.3
                    evidence.append(EvidenceItem(
                        indicator="Suspicious Code Block",
                        description="Code block contains system-level keywords",
                        severity=BreadcrumbSeverity.ORANGE
                    ))

        # Control characters
        if re.search(r'[\x00-\x08\x0e-\x1f\x7f-\x9f]', text):
            score += 0.3
            evidence.append(EvidenceItem(
                indicator="Control Characters",
                description="Hidden control characters detected",
                severity=BreadcrumbSeverity.ORANGE
            ))

        return min(score, 0.9), evidence

    async def _llm_analysis(self, text: str) -> tuple[float, list[EvidenceItem]]:
        settings = get_settings()
        if not settings.groq_api_key:
            return 0.0, []
        try:
            from groq import AsyncGroq
            client = AsyncGroq(api_key=settings.groq_api_key)
            response = await client.chat.completions.create(
                model=settings.groq_model,
                messages=[
                    {"role": "system", "content": (
                        "You are a prompt injection detector. Analyze text and respond ONLY with JSON: "
                        '{"is_injection": true/false, "confidence": 0.0-1.0, "reason": "brief"}'
                    )},
                    {"role": "user", "content": f"Analyze:\n\n{text[:2000]}"}
                ],
                temperature=0.1, max_tokens=200
            )
            result_text = response.choices[0].message.content.strip()
            if "```" in result_text:
                m = re.search(r'```(?:json)?\s*(.*?)```', result_text, re.DOTALL)
                result_text = m.group(1).strip() if m else "{}"
            result = json.loads(result_text)
            conf = float(result.get("confidence", 0.0))
            is_inj = result.get("is_injection", False)
            reason = result.get("reason", "")
            ev = []
            if is_inj and conf > 0.3:
                ev.append(EvidenceItem(
                    indicator="LLM Semantic Analysis",
                    description=f"AI detected injection ({conf:.0%}): {reason}",
                    severity=BreadcrumbSeverity.RED if conf > 0.7 else BreadcrumbSeverity.ORANGE
                ))
            return conf if is_inj else 0.0, ev
        except Exception:
            return 0.0, []

    def _to_severity(self, c: float) -> SeverityLevel:
        if c >= 0.8: return SeverityLevel.CRITICAL
        if c >= 0.6: return SeverityLevel.HIGH
        if c >= 0.4: return SeverityLevel.MEDIUM
        if c >= 0.2: return SeverityLevel.LOW
        return SeverityLevel.SAFE
