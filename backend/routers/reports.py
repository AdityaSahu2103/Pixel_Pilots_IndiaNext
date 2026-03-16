"""
CyberShield AI - Reports Router
Endpoints for fetching and managing scan reports.
"""
from fastapi import APIRouter, HTTPException
from backend.models.schemas import (
    ScanResponse, ScanRequest, SourceType, AdversarialResult
)
from backend.agents.orchestrator import OrchestratorAgent

router = APIRouter(prefix="/api", tags=["Reports"])

# In-memory scan store (production would use a database)
_scan_store: dict[str, ScanResponse] = {}
_orchestrator = OrchestratorAgent()


def store_scan(response: ScanResponse):
    """Store a scan response for later retrieval."""
    _scan_store[response.scan_id] = response


@router.get("/reports/{scan_id}", response_model=ScanResponse)
async def get_report(scan_id: str):
    """Fetch a previously completed scan report."""
    if scan_id not in _scan_store:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return _scan_store[scan_id]


@router.get("/reports", response_model=list[dict])
async def list_reports():
    """List all scan report summaries."""
    summaries = []
    for scan_id, report in _scan_store.items():
        summaries.append({
            "scan_id": scan_id,
            "timestamp": report.timestamp.isoformat(),
            "source_type": report.source_type.value,
            "risk_score": report.risk_score.overall_score,
            "severity": report.risk_score.severity.value,
            "threats_detected": sum(1 for d in report.detections if d.detected)
        })
    return summaries


@router.post("/reports/{scan_id}/adversarial", response_model=AdversarialResult)
async def run_adversarial(scan_id: str):
    """Run adversarial testing on a previously scanned input."""
    if scan_id not in _scan_store:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    report = _scan_store[scan_id]
    original_detected = any(d.detected for d in report.detections)

    # Get original content from the report
    original_content = ""
    for d in report.detections:
        for ev in d.evidence:
            original_content += ev.description + " "

    if not original_content:
        raise HTTPException(status_code=400, detail="No content available for adversarial testing")

    result = await _orchestrator.adversarial_tester.test(
        original_content, original_detected, _orchestrator._detection_scan
    )

    # Update stored report
    report.adversarial = result
    _scan_store[scan_id] = report

    return result
