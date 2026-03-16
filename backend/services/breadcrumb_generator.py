"""
CyberShield AI - Visual Breadcrumb Generator
Generates visual evidence markers for frontend highlighting.
"""
from backend.models.schemas import (
    ThreatDetection, Breadcrumb, BreadcrumbSeverity, ThreatType
)

# Severity to color mapping
SEVERITY_COLORS = {
    BreadcrumbSeverity.RED: "#FF3B30",
    BreadcrumbSeverity.ORANGE: "#FF9500",
    BreadcrumbSeverity.YELLOW: "#FFCC00",
    BreadcrumbSeverity.GREEN: "#34C759",
}


class BreadcrumbGenerator:
    """
    Generates visual breadcrumb data for frontend rendering:
    - Color-coded risk indicators
    - Position-aware evidence highlighting
    - Diff-style consistency markers
    """

    def generate(
        self, detections: list[ThreatDetection], original_content: str = ""
    ) -> list[Breadcrumb]:
        """Generate breadcrumbs from all detection results."""
        breadcrumbs = []

        for detection in detections:
            if not detection.detected:
                continue

            for evidence in detection.evidence:
                # Find position of evidence in original content
                position = None
                if original_content and evidence.indicator:
                    # Try to find the indicator text in content
                    snippet = self._find_relevant_snippet(
                        original_content, evidence
                    )
                else:
                    snippet = evidence.description[:150]

                breadcrumb = Breadcrumb(
                    content_snippet=snippet,
                    threat_type=detection.threat_type,
                    severity=evidence.severity,
                    description=evidence.description,
                    position=evidence.position,
                    highlight_color=SEVERITY_COLORS.get(
                        evidence.severity, "#FFCC00"
                    )
                )
                breadcrumbs.append(breadcrumb)

        # Sort by severity (most severe first)
        severity_order = {
            BreadcrumbSeverity.RED: 0,
            BreadcrumbSeverity.ORANGE: 1,
            BreadcrumbSeverity.YELLOW: 2,
            BreadcrumbSeverity.GREEN: 3,
        }
        breadcrumbs.sort(key=lambda b: severity_order.get(b.severity, 4))

        return breadcrumbs

    def _find_relevant_snippet(
        self, content: str, evidence
    ) -> str:
        """Find and extract the relevant snippet from original content."""
        # If position data is available, use it
        if evidence.position:
            start = evidence.position.get("start", 0)
            end = evidence.position.get("end", min(start + 100, len(content)))
            return content[start:end]

        # Otherwise search for keywords from the indicator
        keywords = evidence.indicator.lower().split()
        content_lower = content.lower()

        for keyword in keywords:
            if len(keyword) < 4:
                continue
            idx = content_lower.find(keyword)
            if idx >= 0:
                start = max(0, idx - 30)
                end = min(len(content), idx + len(keyword) + 70)
                return f"...{content[start:end]}..."

        return evidence.description[:150]
