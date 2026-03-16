"""
CyberShield AI - URL Scanner Agent
Scans URLs for threats using VirusTotal API + heuristic analysis.
"""
import re
import time
import base64
from urllib.parse import urlparse

import httpx

from backend.config import get_settings
from backend.models.schemas import (
    ThreatDetection, ThreatType, SeverityLevel, EvidenceItem,
    BreadcrumbSeverity, ExtractedContent
)


class URLScannerAgent:
    """
    URL threat detection using:
    1. VirusTotal API v3 — multi-engine scanning
    2. Heuristic URL analysis — suspicious patterns
    3. Domain reputation checks
    """

    AGENT_NAME = "url_scanner"

    VT_BASE_URL = "https://www.virustotal.com/api/v3"

    # Suspicious URL patterns
    SUSPICIOUS_PATTERNS = {
        "ip_address_url": re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
        "excessive_subdomains": re.compile(r'https?://([^/]+\.){4,}'),
        "homograph_chars": re.compile(r'[а-яА-Яα-ωΑ-Ω]'),  # Cyrillic/Greek lookalikes
        "encoded_chars": re.compile(r'%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}'),
        "suspicious_tld": re.compile(r'\.(tk|ml|ga|cf|gq|xyz|top|club|work|buzz)(/|$)', re.I),
        "login_keyword": re.compile(r'(login|signin|verify|secure|account|update|confirm|auth|wallet)', re.I),
        "typosquatting": re.compile(r'(g[o0]{2}gle|rnicros0ft|rnicrosoft|appIe|paypaI|faceb[o0]{2}k|netfIix)', re.I),
        "brand_spoofing": re.compile(r'-(google|microsoft|apple|paypal|facebook|amazon|netflix|meta)\.', re.I),
        "multiple_hyphens": re.compile(r'[a-zA-Z0-9]+-[a-zA-Z0-9]+-[a-zA-Z0-9]+-[a-zA-Z0-9]+\.'), # 3+ hyphens in domain
        "long_url": re.compile(r'.{200,}'),
        "at_symbol": re.compile(r'https?://[^/]*@'),
        "double_slash_redirect": re.compile(r'https?://[^/]+//'),
    }

    async def detect(self, extracted: ExtractedContent) -> ThreatDetection:
        """Scan all extracted URLs for threats."""
        start_time = time.time()
        evidence = []
        scores = {}

        urls = extracted.urls
        if not urls:
            # If content looks like a URL, treat it as one
            if re.match(r'https?://', extracted.plain_text.strip()):
                urls = [extracted.plain_text.strip()]

        if not urls:
            return ThreatDetection(
                threat_type=ThreatType.MALICIOUS_URL,
                detected=False,
                confidence=0.0,
                severity=SeverityLevel.SAFE,
                agent_name=self.AGENT_NAME,
                processing_time_ms=(time.time() - start_time) * 1000
            )

        # 1. VirusTotal scan
        vt_score = 0.0
        for url in urls[:5]:  # Limit to 5 URLs for rate limits
            url_vt_score, url_evidence = await self._virustotal_scan(url)
            vt_score = max(vt_score, url_vt_score)
            evidence.extend(url_evidence)
        scores["virustotal"] = vt_score

        # 2. Heuristic analysis
        heuristic_score = 0.0
        for url in urls:
            url_heur_score, url_heur_evidence = self._heuristic_analysis(url)
            heuristic_score = max(heuristic_score, url_heur_score)
            evidence.extend(url_heur_evidence)
        scores["heuristic"] = heuristic_score

        # 3. Redirect chain analysis
        if urls:
            redirect_score, redirect_evidence = await self._check_redirects(urls[0])
            scores["redirect_analysis"] = redirect_score
            evidence.extend(redirect_evidence)

        # Composite confidence
        # Heuristics can be highly confident on their own for obvious spoofing URLs
        confidence = max(vt_score * 0.7 + heuristic_score * 0.3, vt_score, heuristic_score * 0.95)
        confidence = min(confidence, 1.0)

        settings = get_settings()
        detected = confidence >= settings.url_threat_threshold

        severity = self._confidence_to_severity(confidence)
        processing_time = (time.time() - start_time) * 1000

        return ThreatDetection(
            threat_type=ThreatType.MALICIOUS_URL,
            detected=detected,
            confidence=round(confidence, 4),
            severity=severity,
            evidence=evidence,
            raw_scores=scores,
            agent_name=self.AGENT_NAME,
            processing_time_ms=round(processing_time, 2)
        )

    async def _virustotal_scan(self, url: str) -> tuple[float, list[EvidenceItem]]:
        """Scan a URL using VirusTotal API v3."""
        settings = get_settings()
        if not settings.virustotal_api_key:
            return 0.0, []

        try:
            # Encode URL for VT API
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

            headers = {"x-apikey": settings.virustotal_api_key}

            async with httpx.AsyncClient(timeout=15.0) as client:
                # Try to get existing analysis first
                response = await client.get(
                    f"{self.VT_BASE_URL}/urls/{url_id}",
                    headers=headers
                )

                if response.status_code == 404:
                    # Submit for scanning
                    scan_response = await client.post(
                        f"{self.VT_BASE_URL}/urls",
                        headers=headers,
                        data={"url": url}
                    )
                    if scan_response.status_code != 200:
                        return 0.0, []

                    # Get the analysis result
                    scan_data = scan_response.json()
                    analysis_id = scan_data.get("data", {}).get("id", "")
                    if analysis_id:
                        response = await client.get(
                            f"{self.VT_BASE_URL}/analyses/{analysis_id}",
                            headers=headers
                        )

                if response.status_code == 200:
                    data = response.json()
                    attributes = data.get("data", {}).get("attributes", {})
                    
                    # `/analyses` endpoint uses "stats", `/urls` endpoint uses "last_analysis_stats"
                    stats = attributes.get("stats") or attributes.get("last_analysis_stats", {})

                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total = sum(stats.values()) if stats else 1

                    threat_count = malicious + suspicious
                    
                    # Realistic threat scoring based on engine convictions
                    if threat_count == 0:
                        score = 0.0
                    elif threat_count == 1:
                        score = 0.40  # Low confidence, might be false positive
                    elif threat_count == 2:
                        score = 0.65  # Medium-high confidence
                    elif threat_count == 3:
                        score = 0.85  # High confidence
                    else:
                        score = 1.0   # Critical confidence (4+ engines)

                    evidence = []
                    if threat_count > 0:
                        evidence.append(EvidenceItem(
                            indicator="VirusTotal Detection",
                            description=f"{malicious} malicious + {suspicious} suspicious detections out of {total} engines",
                            severity=BreadcrumbSeverity.RED if malicious > 2 else BreadcrumbSeverity.ORANGE
                        ))

                    return score, evidence

            return 0.0, []
        except Exception:
            return 0.0, []

    def _heuristic_analysis(self, url: str) -> tuple[float, list[EvidenceItem]]:
        """Analyze URL for suspicious patterns."""
        evidence = []
        score = 0.0

        for name, pattern in self.SUSPICIOUS_PATTERNS.items():
            if pattern.search(url):
                label = name.replace("_", " ").title()
                severity_map = {
                    "typosquatting": (0.85, BreadcrumbSeverity.RED),
                    "brand_spoofing": (0.8, BreadcrumbSeverity.RED),
                    "ip_address_url": (0.6, BreadcrumbSeverity.ORANGE),
                    "homograph_chars": (0.6, BreadcrumbSeverity.RED),
                    "multiple_hyphens": (0.45, BreadcrumbSeverity.ORANGE),
                    "at_symbol": (0.6, BreadcrumbSeverity.RED),
                    "suspicious_tld": (0.5, BreadcrumbSeverity.ORANGE),
                    "login_keyword": (0.35, BreadcrumbSeverity.YELLOW),
                    "encoded_chars": (0.2, BreadcrumbSeverity.YELLOW),
                    "excessive_subdomains": (0.4, BreadcrumbSeverity.ORANGE),
                    "long_url": (0.15, BreadcrumbSeverity.YELLOW),
                    "double_slash_redirect": (0.4, BreadcrumbSeverity.ORANGE),
                }
                s, sev = severity_map.get(name, (0.1, BreadcrumbSeverity.YELLOW))
                
                # Boost score if login keyword is combined with multiple hyphens or suspicious TLD
                if name == "login_keyword":
                    if self.SUSPICIOUS_PATTERNS["multiple_hyphens"].search(url) or \
                       self.SUSPICIOUS_PATTERNS["suspicious_tld"].search(url):
                        s += 0.3
                        sev = BreadcrumbSeverity.RED
                
                score += s
                evidence.append(EvidenceItem(
                    indicator=label,
                    description=f"URL exhibits '{label}' pattern: {url[:100]}",
                    severity=sev
                ))

        return min(score, 1.0), evidence

    async def _check_redirects(self, url: str) -> tuple[float, list[EvidenceItem]]:
        """Check redirect chains for suspicious behavior."""
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
                response = await client.head(url)
                redirect_count = len(response.history)

                if redirect_count > 3:
                    return 0.3, [EvidenceItem(
                        indicator="Excessive Redirects",
                        description=f"URL redirects {redirect_count} times before reaching destination",
                        severity=BreadcrumbSeverity.ORANGE
                    )]
                elif redirect_count > 1:
                    return 0.1, [EvidenceItem(
                        indicator="Multiple Redirects",
                        description=f"URL has {redirect_count} redirects",
                        severity=BreadcrumbSeverity.YELLOW
                    )]
        except Exception:
            pass

        return 0.0, []

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
