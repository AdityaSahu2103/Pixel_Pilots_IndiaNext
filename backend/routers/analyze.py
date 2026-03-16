"""
CyberShield AI - Analyze Router
Main scan endpoints for threat detection.
"""
from fastapi import APIRouter, HTTPException
from backend.models.schemas import (
    ScanRequest, ScanResponse, EmailScanRequest,
    URLScanRequest, TextScanRequest, SourceType
)
from backend.agents.orchestrator import OrchestratorAgent

router = APIRouter(prefix="/api", tags=["Analysis"])

# Singleton orchestrator
orchestrator = OrchestratorAgent()


@router.post("/analyze", response_model=ScanResponse)
async def analyze(request: ScanRequest):
    """
    Main threat analysis endpoint.
    Accepts any source type and runs the full multi-agent pipeline.
    """
    try:
        result = await orchestrator.scan(request)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/analyze/email", response_model=ScanResponse)
async def analyze_email(request: EmailScanRequest):
    """Analyze email content for threats."""
    scan_request = ScanRequest(
        source_type=SourceType.EMAIL,
        content=request.raw_email,
        metadata={
            "sender": request.sender,
            "subject": request.subject
        }
    )
    try:
        result = await orchestrator.scan(scan_request)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Email scan failed: {str(e)}")


@router.post("/analyze/url", response_model=ScanResponse)
async def analyze_url(request: URLScanRequest):
    """Analyze a URL for threats."""
    scan_request = ScanRequest(
        source_type=SourceType.URL,
        content=request.url,
        metadata={"follow_redirects": request.follow_redirects}
    )
    try:
        result = await orchestrator.scan(scan_request)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"URL scan failed: {str(e)}")


@router.post("/analyze/text", response_model=ScanResponse)
async def analyze_text(request: TextScanRequest):
    """Analyze text/message content for threats."""
    scan_request = ScanRequest(
        source_type=SourceType.TEXT,
        content=request.text,
        metadata={"context": request.context} if request.context else None
    )
    try:
        result = await orchestrator.scan(scan_request)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Text scan failed: {str(e)}")


from fastapi import File, UploadFile
@router.post("/analyze/file", response_model=ScanResponse)
async def analyze_file(file: UploadFile = File(...)):
    """Analyze direct media file uploads (for deepfakes or general analysis)."""
    try:
        content_bytes = await file.read()
        scan_request = ScanRequest(
            source_type=SourceType.FILE,
            content="Binary content uploaded via API.",
            metadata={
                "file_content": content_bytes,
                "content_type": file.content_type,
                "filename": file.filename
            }
        )
        result = await orchestrator.scan(scan_request)
        return result
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"File scan failed: {str(e)}")
    finally:
        await file.close()
