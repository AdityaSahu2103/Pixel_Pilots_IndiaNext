"""
CyberShield AI - Phishing Detection Agent
Detects phishing attempts using Google Safe Browsing API + NLP heuristics.
"""
import re
import time
from typing import Optional

import httpx

from backend.config import get_settings
from backend.models.schemas import (
    ThreatDetection, ThreatType, SeverityLevel, EvidenceItem,
    BreadcrumbSeverity, ExtractedContent
)


class PhishingDetectorAgent:
    """
    Multi-layered phishing detection:
    1. Google Safe Browsing API for URL-level checks
    2. Email header analysis (SPF, DKIM, DMARC)
    3. NLP-based urgency/social engineering detection
    4. Link-text mismatch detection
    5. Sender domain reputation
    """

    AGENT_NAME = "phishing_detector"

    # Social engineering urgency keywords
    URGENCY_KEYWORDS = [
        "urgent", "immediate", "action required", "verify your account",
        "suspend", "locked", "unauthorized", "confirm your identity",
        "click here", "within 24 hours", "limited time", "act now",
        "your account will be", "security alert", "unusual activity",
        "password expired", "verify now", "update your payment",
        "billing information", "won a prize", "congratulations",
        "you have been selected", "claim your reward", "risk of closure"
    ]

    # Suspicious sender patterns
    SUSPICIOUS_SENDER_PATTERNS = [
        r'no-?reply@',
        r'support@.*\.(tk|ml|ga|cf|gq)',  # Free domain TLDs
        r'.*@.*\.ru$',
        r'.*@.*-.*-.*\.com',  # Multi-hyphen domains
        r'admin@(?!google|microsoft|apple|amazon)',
    ]

    # Known legitimate domains (for mismatch detection)
    LEGITIMATE_DOMAINS = [
        "google.com", "microsoft.com", "apple.com", "amazon.com",
        "paypal.com", "facebook.com", "instagram.com", "twitter.com",
        "linkedin.com", "github.com", "netflix.com", "spotify.com"
    ]

    GOOGLE_SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    async def detect(self, extracted: ExtractedContent) -> ThreatDetection:
        """Run all phishing detection checks."""
        start_time = time.time()
        evidence = []
        scores = {}

        # 1. Google Safe Browsing check on URLs
        gsb_score = await self._check_safe_browsing(extracted.urls)
        scores["google_safe_browsing"] = gsb_score
        if gsb_score > 0:
            evidence.append(EvidenceItem(
                indicator="Google Safe Browsing Match",
                description=f"One or more URLs flagged by Google Safe Browsing (score: {gsb_score:.2f})",
                severity=BreadcrumbSeverity.RED
            ))

        # 2. Email header analysis
        if extracted.headers:
            header_score, header_evidence = self._analyze_headers(extracted.headers)
            scores["header_analysis"] = header_score
            evidence.extend(header_evidence)

        # 3. Urgency/social engineering detection
        urgency_score, urgency_evidence = self._detect_urgency(extracted.plain_text)
        scores["urgency_detection"] = urgency_score
        evidence.extend(urgency_evidence)

        # 4. Link-text mismatch detection
        if extracted.html_content:
            mismatch_score, mismatch_evidence = self._detect_link_mismatch(extracted.html_content)
            scores["link_mismatch"] = mismatch_score
            evidence.extend(mismatch_evidence)

        # 4b. Explicit Domain Spoofing Check on URLs
        spoof_score, spoof_evidence = self._detect_url_spoofing(extracted.urls)
        scores["url_spoofing"] = spoof_score
        evidence.extend(spoof_evidence)

        # 5. Sender reputation
        if getattr(extracted, "sender", None):
            sender_score, sender_evidence = self._check_sender(extracted.sender)
            scores["sender_reputation"] = sender_score
            evidence.extend(sender_evidence)

        # Calculate composite confidence
        active_scores = [v for v in scores.values() if v > 0]
        confidence = max(active_scores) if active_scores else 0.0

        # Boost confidence if multiple signals agree
        if len(active_scores) >= 2:
            confidence = min(confidence * 1.2, 1.0)
        if len(active_scores) >= 3:
            confidence = min(confidence * 1.1, 1.0)

        settings = get_settings()
        detected = confidence >= settings.phishing_threshold

        severity = self._confidence_to_severity(confidence)

        processing_time = (time.time() - start_time) * 1000

        return ThreatDetection(
            threat_type=ThreatType.PHISHING,
            detected=detected,
            confidence=round(confidence, 4),
            severity=severity,
            evidence=evidence,
            raw_scores=scores,
            agent_name=self.AGENT_NAME,
            processing_time_ms=round(processing_time, 2)
        )

    async def _check_safe_browsing(self, urls: list[str]) -> float:
        """Check URLs against Google Safe Browsing API."""
        settings = get_settings()
        if not settings.google_safe_browsing_api_key or not urls:
            return 0.0

        try:
            payload = {
                "client": {
                    "clientId": "cybershield-ai",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE", "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url} for url in urls[:10]]
                }
            }

            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    f"{self.GOOGLE_SAFE_BROWSING_URL}?key={settings.google_safe_browsing_api_key}",
                    json=payload
                )

                if response.status_code == 200:
                    data = response.json()
                    matches = data.get("matches", [])
                    if matches:
                        # Score based on number and type of matches
                        return min(0.5 + (len(matches) * 0.15), 1.0)
                return 0.0
        except Exception:
            return 0.0

    def _analyze_headers(self, headers: dict) -> tuple[float, list[EvidenceItem]]:
        """Analyze email headers for authentication failures."""
        score = 0.0
        evidence = []

        # Check SPF
        spf = headers.get("spf", "").lower()
        if "fail" in spf or "softfail" in spf:
            score += 0.3
            evidence.append(EvidenceItem(
                indicator="SPF Failure",
                description=f"SPF check failed: {spf[:100]}",
                severity=BreadcrumbSeverity.RED
            ))
        elif "pass" not in spf and spf:
            score += 0.1
            evidence.append(EvidenceItem(
                indicator="SPF Neutral",
                description="SPF check returned neutral/unknown result",
                severity=BreadcrumbSeverity.YELLOW
            ))

        # Check DKIM
        dkim = headers.get("dkim_signature", "")
        auth_results = headers.get("authentication_results", "").lower()
        if "dkim=fail" in auth_results:
            score += 0.3
            evidence.append(EvidenceItem(
                indicator="DKIM Failure",
                description="DKIM signature verification failed",
                severity=BreadcrumbSeverity.RED
            ))
        elif not dkim:
            score += 0.15
            evidence.append(EvidenceItem(
                indicator="No DKIM Signature",
                description="Email lacks DKIM signature — cannot verify sender authenticity",
                severity=BreadcrumbSeverity.ORANGE
            ))

        # Check DMARC
        if "dmarc=fail" in auth_results:
            score += 0.3
            evidence.append(EvidenceItem(
                indicator="DMARC Failure",
                description="DMARC policy check failed",
                severity=BreadcrumbSeverity.RED
            ))

        # Check Reply-To mismatch
        reply_to = headers.get("reply_to", "")
        from_addr = headers.get("from", "")
        if reply_to and from_addr and reply_to.lower() != from_addr.lower():
            score += 0.2
            evidence.append(EvidenceItem(
                indicator="Reply-To Mismatch",
                description=f"Reply-To ({reply_to}) differs from From ({from_addr})",
                severity=BreadcrumbSeverity.ORANGE
            ))

        return min(score, 1.0), evidence

    def _detect_urgency(self, text: str) -> tuple[float, list[EvidenceItem]]:
        """Detect social engineering urgency patterns."""
        text_lower = text.lower()
        found_keywords = []

        for keyword in self.URGENCY_KEYWORDS:
            if keyword in text_lower:
                found_keywords.append(keyword)

        if not found_keywords:
            return 0.0, []

        score = min(len(found_keywords) * 0.12, 0.85)
        evidence = [EvidenceItem(
            indicator="Social Engineering Patterns",
            description=f"Found {len(found_keywords)} urgency/manipulation keywords: {', '.join(found_keywords[:5])}",
            severity=BreadcrumbSeverity.ORANGE if score < 0.5 else BreadcrumbSeverity.RED,
            position={"keywords": found_keywords}
        )]

        return score, evidence

    def _detect_link_mismatch(self, html_content: str) -> tuple[float, list[EvidenceItem]]:
        """Detect mismatches between displayed link text and actual href."""
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html_content, "html.parser")
        evidence = []
        mismatches = 0

        for link in soup.find_all("a", href=True):
            href = link.get("href", "")
            display_text = link.get_text().strip()

            # Check if display text looks like a URL
            if re.match(r'https?://', display_text):
                from urllib.parse import urlparse
                displayed_domain = urlparse(display_text).netloc
                actual_domain = urlparse(href).netloc

                if displayed_domain and actual_domain and displayed_domain != actual_domain:
                    mismatches += 1
                    evidence.append(EvidenceItem(
                        indicator="Link-Text Mismatch",
                        description=f"Displayed: {displayed_domain} → Actual: {actual_domain}",
                        severity=BreadcrumbSeverity.RED
                    ))

        score = min(mismatches * 0.3, 0.9) if mismatches > 0 else 0.0
        return score, evidence

    def _detect_url_spoofing(self, urls: list[str]) -> tuple[float, list[EvidenceItem]]:
        """Check URLs for typosquatting or brand impersonation."""
        from urllib.parse import urlparse
        evidence = []
        score = 0.0

        for url in urls:
            try:
                domain = urlparse(url).netloc.lower()
                if not domain:
                    continue
                
                # Check for lookalike domains
                for legit_domain in self.LEGITIMATE_DOMAINS:
                    base = legit_domain.split(".")[0]
                    # Direct lookalike: g00gle.com
                    if re.search(base.replace('o', '[o0]').replace('i', '[il1]'), domain) and legit_domain not in domain:
                        score += 0.85
                        evidence.append(EvidenceItem(
                            indicator="Brand Impersonation URL",
                            description=f"URL domain '{domain}' is attempting to spoof {legit_domain}",
                            severity=BreadcrumbSeverity.RED
                        ))
                    # Subdomain spoofing: login.google.com.badsite.com or login-google.com
                    elif base in domain and not domain.endswith(legit_domain):
                        score += 0.75
                        evidence.append(EvidenceItem(
                            indicator="Brand Impersonation URL",
                            description=f"URL '{domain}' contains '{base}' but is not the official domain",
                            severity=BreadcrumbSeverity.RED
                        ))
            except Exception:
                pass

        return min(score, 1.0), evidence

    def _check_sender(self, sender: str) -> tuple[float, list[EvidenceItem]]:
        """Check sender address for suspicious patterns."""
        evidence = []
        score = 0.0

        for pattern in self.SUSPICIOUS_SENDER_PATTERNS:
            if re.search(pattern, sender, re.IGNORECASE):
                score += 0.2
                evidence.append(EvidenceItem(
                    indicator="Suspicious Sender",
                    description=f"Sender '{sender}' matches suspicious pattern",
                    severity=BreadcrumbSeverity.ORANGE
                ))
                break

        # Check for lookalike domains
        for legit_domain in self.LEGITIMATE_DOMAINS:
            base = legit_domain.split(".")[0]
            if base in sender.lower() and legit_domain.lower() not in sender.lower():
                score += 0.65
                evidence.append(EvidenceItem(
                    indicator="Domain Spoofing Attempt",
                    description=f"Sender domain appears to impersonate {legit_domain}",
                    severity=BreadcrumbSeverity.RED
                ))
                break

        return min(score, 1.0), evidence

    def _confidence_to_severity(self, confidence: float) -> SeverityLevel:
        """Map confidence score to severity level."""
        if confidence >= 0.8:
            return SeverityLevel.CRITICAL
        elif confidence >= 0.6:
            return SeverityLevel.HIGH
        elif confidence >= 0.4:
            return SeverityLevel.MEDIUM
        elif confidence >= 0.2:
            return SeverityLevel.LOW
        return SeverityLevel.SAFE
