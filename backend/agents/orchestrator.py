"""
CyberShield AI - Orchestrator Agent
Central coordinator that manages the entire scan pipeline.
"""
import asyncio
import time
from typing import Optional

from backend.agents.content_extractor import ContentExtractorAgent
from backend.agents.phishing_detector import PhishingDetectorAgent
from backend.agents.url_scanner import URLScannerAgent
from backend.agents.deepfake_analyzer import DeepfakeAnalyzerAgent
from backend.agents.prompt_injection import PromptInjectionAgent
from backend.agents.anomaly_detector import AnomalyDetectorAgent
from backend.agents.cross_validator import CrossValidatorAgent
from backend.llm.explainer import ExplainerAgent
from backend.llm.context_enricher import ContextEnricher
from backend.services.breadcrumb_generator import BreadcrumbGenerator
from backend.services.adversarial_tester import AdversarialTester
from backend.models.schemas import (
    ScanRequest, ScanResponse, ExtractedContent, SourceType,
    ThreatDetection
)
from backend.models.risk_calculator import calculate_risk_score, _score_to_severity
from backend.config import get_settings


class OrchestratorAgent:
    """
    Central coordinator for the multi-agent detection pipeline.
    Flow: Extract → Detect (parallel) → Cross-validate → Explain → Breadcrumbs
    """

    def __init__(self):
        self.content_extractor = ContentExtractorAgent()
        self.phishing_detector = PhishingDetectorAgent()
        self.url_scanner = URLScannerAgent()
        self.deepfake_analyzer = DeepfakeAnalyzerAgent()
        self.prompt_injection = PromptInjectionAgent()
        self.anomaly_detector = AnomalyDetectorAgent()
        self.cross_validator = CrossValidatorAgent()
        self.explainer = ExplainerAgent()
        self.context_enricher = ContextEnricher()
        self.breadcrumb_generator = BreadcrumbGenerator()
        self.adversarial_tester = AdversarialTester()

    async def scan(self, request: ScanRequest) -> ScanResponse:
        """Execute the full scan pipeline."""
        start_time = time.time()

        # Step 1: Content Extraction
        extracted = await self.content_extractor.extract(
            request.source_type, request.content, request.metadata
        )

        # Step 2: Parallel Detection
        detections = await self._run_detections(extracted)

        # Step 3: Cross-Validation
        cross_result = self.cross_validator.validate(detections)
        validated = cross_result.validated_detections

        # Step 4: Risk Scoring
        risk_score = calculate_risk_score(validated)

        # Step 5: Context Enrichment + LLM Explanation
        context = await self.context_enricher.enrich(validated)
        explanation = await self.explainer.explain(
            validated, risk_score, context, extracted.plain_text
        )

        settings = get_settings()

        # OVERRIDE SCORING WITH LLM Output (if available)
        if explanation.llm_risk_score is not None:
            new_overall = explanation.llm_risk_score
            risk_score.overall_score = round(new_overall, 2)
            risk_score.severity = _score_to_severity(new_overall)

        if explanation.llm_threat_scores:
            threat_scores = explanation.llm_threat_scores
            max_conf = risk_score.confidence
            
            for det in validated:
                threat_key = det.threat_type.value
                if threat_key in threat_scores:
                    new_conf = threat_scores[threat_key]
                    det.confidence = round(new_conf, 4)
                    
                    # Update detected boolean based on new confidence
                    threshold_map = {
                        "phishing": settings.phishing_threshold,
                        "malicious_url": settings.url_threat_threshold,
                        "deepfake": settings.deepfake_threshold,
                        "prompt_injection": settings.prompt_injection_threshold,
                        "anomaly": settings.anomaly_threshold,
                        "ai_generated": settings.deepfake_threshold
                    }
                    threshold = threshold_map.get(threat_key, 0.5)
                    det.detected = new_conf >= threshold
                    
                    # Update severity
                    det.severity = _score_to_severity(new_conf * 100)
                    
                    max_conf = max(max_conf, new_conf)
                    
                    # Update breakdown risk score
                    for breakdown in risk_score.breakdown:
                        if breakdown.threat_type == det.threat_type:
                            breakdown.score = new_conf * 100

            risk_score.confidence = round(max_conf, 3)

        # Step 6: Visual Breadcrumbs
        breadcrumbs = self.breadcrumb_generator.generate(
            validated, extracted.plain_text
        )

        # Step 7: Adversarial Testing (optional)
        adversarial = None
        if request.enable_adversarial:
            original_detected = any(d.detected for d in validated)
            adversarial = await self.adversarial_tester.test(
                request.content, original_detected, self._detection_scan
            )

        processing_time = (time.time() - start_time) * 1000

        return ScanResponse(
            source_type=request.source_type,
            risk_score=risk_score,
            detections=validated,
            cross_validation=cross_result,
            explanation=explanation,
            breadcrumbs=breadcrumbs,
            adversarial=adversarial,
            processing_time_ms=round(processing_time, 2)
        )

    async def _run_detections(self, extracted: ExtractedContent) -> list[ThreatDetection]:
        """Run all detection agents in parallel."""
        tasks = [
            self.phishing_detector.detect(extracted),
            self.url_scanner.detect(extracted),
            self.deepfake_analyzer.detect(extracted),
            self.prompt_injection.detect(extracted),
            self.anomaly_detector.detect(extracted),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        detections = []
        for result in results:
            if isinstance(result, ThreatDetection):
                detections.append(result)
            elif isinstance(result, Exception):
                # Log but don't fail the pipeline
                pass

        return detections

    async def _detection_scan(self, extracted: ExtractedContent) -> list[ThreatDetection]:
        """Minimal detection scan for adversarial testing."""
        return await self._run_detections(extracted)

    def get_agent_status(self) -> dict:
        """Get status of all agents."""
        return {
            "content_extractor": "active",
            "phishing_detector": "active",
            "url_scanner": "active",
            "deepfake_analyzer": "active",
            "prompt_injection_detector": "active",
            "anomaly_detector": "active",
            "cross_validator": "active",
            "llm_explainer": "active",
            "context_enricher": "active",
            "breadcrumb_generator": "active",
            "adversarial_tester": "active",
        }
