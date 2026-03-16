"""
DeepShield FastAPI Backend
Powered by Reality Defender API (Free Tier)

Run:
    pip install -r requirements.txt
    uvicorn main:app --reload --host 0.0.0.0 --port 8000

Endpoints:
    GET  /                      Health check
    POST /analyze/image         Analyze an image file
    POST /analyze/audio         Analyze an audio file
    POST /analyze/video         Analyze a video (frame + audio pipeline)
    GET  /result/{request_id}   Fetch any result by RD request ID
"""

import asyncio
import logging
import os
import tempfile
import time
from datetime import datetime
from typing import Optional

import numpy as np
from fastapi import FastAPI, File, HTTPException, Query, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import rd_client
import video_utils

# ─── LOGGING ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt = "%H:%M:%S",
)
logger = logging.getLogger("main")

# ─── CONFIG ──────────────────────────────────────────────────────────────────
API_KEY     = os.getenv("RD_API_KEY", "rd_62f58d54d55a2918_274af570574c797a2e27c1c394226003")
NUM_FRAMES  = int(os.getenv("NUM_FRAMES", "5"))

# Allowed MIME types per endpoint
ALLOWED_IMAGE = {"image/jpeg", "image/png", "image/webp", "image/gif", "image/jpg"}
ALLOWED_AUDIO = {"audio/mpeg", "audio/wav", "audio/x-wav", "audio/mp4",
                 "audio/aac", "audio/ogg", "audio/flac", "audio/x-flac",
                 "audio/m4a", "audio/x-m4a"}
ALLOWED_VIDEO = {"video/mp4", "video/quicktime", "video/x-msvideo"}

# ─── PYDANTIC RESPONSE MODELS ────────────────────────────────────────────────

class ModelScore(BaseModel):
    name : str
    score: float

class AnalyzeResponse(BaseModel):
    success           : bool
    status            : str                       # FAKE | AUTHENTIC | SUSPICIOUS | NOT_APPLICABLE | UNABLE_TO_EVALUATE | ERROR
    score             : float                     # 0-100
    confidence        : str                       # HIGH | MEDIUM | LOW
    media_type        : str                       # IMAGE | AUDIO | VIDEO
    request_id        : Optional[str]   = None
    filename          : str
    file_size_bytes   : int
    processing_time_ms: int
    analyzed_at       : str
    models            : list[ModelScore] = []

    # Video-only fields
    frame_scores      : Optional[list[float]] = None
    frame_statuses    : Optional[list[str]]   = None
    audio_score       : Optional[float]       = None
    audio_status      : Optional[str]         = None
    video_metadata    : Optional[dict]        = None
    mean_score        : Optional[float]       = None
    peak_score        : Optional[float]       = None

    # Error info
    error             : Optional[str]         = None
    rd_raw            : Optional[dict]        = None   # full RD response (debug)

class HealthResponse(BaseModel):
    status       : str
    version      : str
    api_connected: bool
    timestamp    : str

# ─── APP SETUP ───────────────────────────────────────────────────────────────

app = FastAPI(
    title       = "DeepShield API",
    description = "Deepfake detection powered by Reality Defender — Free Tier compatible",
    version     = "1.0.0",
    docs_url    = "/docs",
    redoc_url   = "/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins     = [
        "http://localhost:3000",
        "http://localhost:3001",
        "https://*.vercel.app",      # Vercel preview deployments
        "https://your-production-domain.com",  # ← replace with your domain
    ],
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)


# ─── INTERNAL HELPERS ────────────────────────────────────────────────────────

def _build_models(raw_result: dict) -> list[ModelScore]:
    """Extract per-model scores from raw RD result."""
    models = raw_result.get("models") or []
    out    = []
    for m in models:
        name  = m.get("name") or m.get("modelName") or m.get("model") or "Unknown"
        raw   = m.get("score") or m.get("probability") or m.get("finalScore") or 0
        score = float(raw) * 100 if float(raw) <= 1 else float(raw)
        out.append(ModelScore(name=name, score=round(min(max(score, 0), 100), 2)))
    return out


def _get_request_id(raw_result: dict) -> str | None:
    return raw_result.get("requestId") or raw_result.get("request_id") or raw_result.get("mediaId")


def _combined_verdict(scores: list[float]) -> tuple[float, float, float, str]:
    """
    Given a list of scores, compute:
      mean_score, peak_score, final_score (weighted), status string
    """
    mean  = float(np.mean(scores))
    peak  = float(np.max(scores))
    final = mean * 0.7 + peak * 0.3        # weight peak heavily

    if final >= 70 or peak >= 85:
        st = "FAKE"
    elif final >= 40 or peak >= 65:
        st = "SUSPICIOUS"
    else:
        st = "AUTHENTIC"

    return round(mean,2), round(peak,2), round(final,2), st


def _validate_file_size(size: int, max_mb: int, label: str):
    if size > max_mb * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"{label} exceeds {max_mb} MB limit (got {size/1024/1024:.1f} MB)",
        )


def _validate_mime(content_type: str, allowed: set, label: str):
    # Normalise: "image/jpeg; charset=..." → "image/jpeg"
    ct = (content_type or "").split(";")[0].strip().lower()
    if ct not in allowed:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"Unsupported {label} type '{ct}'. Allowed: {sorted(allowed)}",
        )


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

# ── GET / — Health check ──────────────────────────────────────────────────────
@app.get("/", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """Quick health check — also verifies the RD API key is accepted."""
    api_ok = False
    try:
        import httpx
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(
                "https://api.prd.realitydefender.xyz/api/media/users",
                headers={"X-API-KEY": API_KEY},
            )
            # 200 or 404 both mean the key is valid; 401/403 means bad key
            api_ok = r.status_code not in (401, 403)
    except Exception:
        pass

    return HealthResponse(
        status        = "ok",
        version       = "1.0.0",
        api_connected = api_ok,
        timestamp     = datetime.utcnow().isoformat() + "Z",
    )


# ── POST /analyze/image ───────────────────────────────────────────────────────
@app.post("/analyze/image", response_model=AnalyzeResponse, tags=["Analysis"])
async def analyze_image(
    file      : UploadFile = File(..., description="Image file — jpg/png/webp/gif, max 50 MB"),
    debug     : bool       = Query(False, description="Include raw RD API response in output"),
):
    """
    Analyze an image for deepfake manipulation.
    Returns verdict, score 0-100, confidence, and per-model breakdown.
    """
    t_start = time.time()
    content = await file.read()

    _validate_file_size(len(content), 50, "Image")
    _validate_mime(file.content_type or "", ALLOWED_IMAGE, "image")

    logger.info("Image analysis: %s  size=%d bytes", file.filename, len(content))

    try:
        raw = await rd_client.analyze_file(API_KEY, content, file.filename or "upload.jpg")
    except ValueError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        logger.exception("RD API error on image analysis")
        raise HTTPException(status_code=502, detail=f"Reality Defender API error: {exc}")

    if raw is None:
        raise HTTPException(status_code=504, detail="Analysis timed out. Try again or use a smaller file.")

    score, st = rd_client.parse_score_and_status(raw)
    elapsed   = int((time.time() - t_start) * 1000)

    return AnalyzeResponse(
        success            = True,
        status             = st,
        score              = round(score, 2),
        confidence         = rd_client.score_to_confidence(score),
        media_type         = "IMAGE",
        request_id         = _get_request_id(raw),
        filename           = file.filename or "upload.jpg",
        file_size_bytes    = len(content),
        processing_time_ms = elapsed,
        analyzed_at        = datetime.utcnow().isoformat() + "Z",
        models             = _build_models(raw),
        rd_raw             = raw if debug else None,
    )


# ── POST /analyze/audio ───────────────────────────────────────────────────────
@app.post("/analyze/audio", response_model=AnalyzeResponse, tags=["Analysis"])
async def analyze_audio(
    file  : UploadFile = File(..., description="Audio file — mp3/wav/m4a/aac/ogg/flac, max 20 MB"),
    debug : bool       = Query(False, description="Include raw RD API response in output"),
):
    """
    Analyze an audio file for AI-cloned / synthetic voice.
    Returns verdict, score 0-100, confidence, and per-model breakdown.
    """
    t_start = time.time()
    content = await file.read()

    _validate_file_size(len(content), 20, "Audio")
    _validate_mime(file.content_type or "", ALLOWED_AUDIO, "audio")

    logger.info("Audio analysis: %s  size=%d bytes", file.filename, len(content))

    try:
        raw = await rd_client.analyze_file(API_KEY, content, file.filename or "upload.wav")
    except ValueError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        logger.exception("RD API error on audio analysis")
        raise HTTPException(status_code=502, detail=f"Reality Defender API error: {exc}")

    if raw is None:
        raise HTTPException(status_code=504, detail="Analysis timed out. Try a shorter clip.")

    score, st = rd_client.parse_score_and_status(raw)
    elapsed   = int((time.time() - t_start) * 1000)

    return AnalyzeResponse(
        success            = True,
        status             = st,
        score              = round(score, 2),
        confidence         = rd_client.score_to_confidence(score),
        media_type         = "AUDIO",
        request_id         = _get_request_id(raw),
        filename           = file.filename or "upload.wav",
        file_size_bytes    = len(content),
        processing_time_ms = elapsed,
        analyzed_at        = datetime.utcnow().isoformat() + "Z",
        models             = _build_models(raw),
        rd_raw             = raw if debug else None,
    )


# ── POST /analyze/video ───────────────────────────────────────────────────────
@app.post("/analyze/video", response_model=AnalyzeResponse, tags=["Analysis"])
async def analyze_video(
    file      : UploadFile = File(..., description="Video file — mp4/mov, max 250 MB"),
    n_frames  : int        = Query(5, ge=1, le=10, description="Key frames to extract (1-10)"),
    debug     : bool       = Query(False, description="Include raw RD API response in output"),
):
    """
    Analyze a video for deepfakes using the free-tier pipeline:
      1. Extract n_frames key frames → analyze each as image
      2. Extract audio track via ffmpeg → analyze as audio
      3. Combine scores (mean × 0.7 + peak × 0.3) into final verdict

    Each video consumes up to n_frames + 1 free-tier scans.
    """
    t_start = time.time()
    content = await file.read()

    _validate_file_size(len(content), 250, "Video")
    _validate_mime(file.content_type or "", ALLOWED_VIDEO, "video")

    logger.info("Video analysis: %s  size=%.1f MB  n_frames=%d",
                file.filename, len(content)/1024/1024, n_frames)

    # ── Write to temp file (OpenCV needs a path) ──────────────────────────────
    with tempfile.NamedTemporaryFile(delete=False, suffix=".mp4") as tmp:
        tmp.write(content)
        video_path = tmp.name

    try:
        # ── Video metadata ────────────────────────────────────────────────────
        vid_meta = video_utils.get_video_metadata(video_path)
        logger.info("Video metadata: %s", vid_meta)

        # ── Extract frames ────────────────────────────────────────────────────
        frames = await video_utils.extract_key_frames_async(video_path, n_frames)

        if not frames:
            raise HTTPException(
                status_code=422,
                detail="Could not extract frames. File may be corrupt or unsupported.",
            )

        # ── Analyze frames concurrently ───────────────────────────────────────
        async def analyze_frame(idx: int, frame_bgr) -> dict | None:
            jpg_bytes = video_utils.encode_frame_jpeg(frame_bgr)
            fname     = f"frame_{idx:02d}_{file.filename or 'video'}.jpg"
            try:
                return await rd_client.analyze_file(API_KEY, jpg_bytes, fname)
            except Exception as exc:
                logger.warning("Frame %d analysis failed: %s", idx, exc)
                return None

        frame_tasks   = [analyze_frame(i+1, frm) for i, (_, frm) in enumerate(frames)]
        frame_results = await asyncio.gather(*frame_tasks)

        frame_scores   = []
        frame_statuses = []
        all_scores     = []

        for res in frame_results:
            if res is None:
                frame_scores.append(0.0)
                frame_statuses.append("ERROR")
                continue
            sc, st = rd_client.parse_score_and_status(res)
            frame_scores.append(round(sc, 2))
            frame_statuses.append(st)
            if st not in ("NOT_APPLICABLE", "UNABLE_TO_EVALUATE", "ERROR"):
                all_scores.append(sc)

        # ── Extract + analyze audio ───────────────────────────────────────────
        audio_score  = None
        audio_status = None
        audio_raw    = None

        audio_tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".wav")
        audio_tmp.close()
        audio_path = audio_tmp.name

        audio_extracted = await video_utils.extract_audio_async(video_path, audio_path)

        if audio_extracted:
            try:
                with open(audio_path, "rb") as af:
                    audio_bytes = af.read()
                afname    = f"audio_{file.filename or 'video'}.wav"
                audio_raw = await rd_client.analyze_file(API_KEY, audio_bytes, afname)
                if audio_raw:
                    a_sc, a_st = rd_client.parse_score_and_status(audio_raw)
                    audio_score  = round(a_sc, 2)
                    audio_status = a_st
                    if a_st not in ("NOT_APPLICABLE", "UNABLE_TO_EVALUATE"):
                        all_scores.append(a_sc)
                    logger.info("Audio analysis done: status=%s score=%.1f", a_st, a_sc)
            except Exception as exc:
                logger.warning("Audio analysis failed: %s", exc)
            finally:
                if os.path.exists(audio_path):
                    os.unlink(audio_path)
        else:
            if os.path.exists(audio_path):
                os.unlink(audio_path)

        # ── Combine scores ────────────────────────────────────────────────────
        if not all_scores:
            raise HTTPException(
                status_code=422,
                detail="No usable scores returned. All frames may be NOT_APPLICABLE (no face detected).",
            )

        mean_sc, peak_sc, final_sc, combined_st = _combined_verdict(all_scores)
        elapsed = int((time.time() - t_start) * 1000)

        # Aggregate model scores across all frame results (deduplicate by name)
        model_map: dict[str, list[float]] = {}
        for res in frame_results:
            if res is None:
                continue
            for m in (res.get("models") or []):
                name  = m.get("name") or m.get("modelName") or "Unknown"
                raw   = m.get("score") or m.get("probability") or 0
                score = float(raw) * 100 if float(raw) <= 1 else float(raw)
                model_map.setdefault(name, []).append(score)

        agg_models = [
            ModelScore(name=name, score=round(float(np.mean(scores)), 2))
            for name, scores in model_map.items()
        ]

        logger.info(
            "Video analysis done: status=%s final_score=%.1f mean=%.1f peak=%.1f elapsed=%dms",
            combined_st, final_sc, mean_sc, peak_sc, elapsed,
        )

        return AnalyzeResponse(
            success            = True,
            status             = combined_st,
            score              = final_sc,
            confidence         = rd_client.score_to_confidence(final_sc),
            media_type         = "VIDEO",
            request_id         = None,   # video uses multiple request IDs
            filename           = file.filename or "upload.mp4",
            file_size_bytes    = len(content),
            processing_time_ms = elapsed,
            analyzed_at        = datetime.utcnow().isoformat() + "Z",
            models             = agg_models,
            frame_scores       = frame_scores,
            frame_statuses     = frame_statuses,
            audio_score        = audio_score,
            audio_status       = audio_status,
            video_metadata     = vid_meta,
            mean_score         = mean_sc,
            peak_score         = peak_sc,
            rd_raw             = None,  # too large for video
        )

    finally:
        if os.path.exists(video_path):
            os.unlink(video_path)


# ── GET /result/{request_id} ─────────────────────────────────────────────────
@app.get("/result/{request_id}", response_model=AnalyzeResponse, tags=["Analysis"])
async def get_result(
    request_id: str,
    debug      : bool = Query(False, description="Include raw RD API response in output"),
):
    """
    Fetch a result from Reality Defender by request ID.
    Useful if you want to implement async polling from your frontend:
    submit → store request_id → poll this endpoint until status is final.
    """
    t_start = time.time()
    logger.info("Fetching result for request_id=%s", request_id)

    import httpx
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.get(
                f"https://api.prd.realitydefender.xyz/api/media/users/{request_id}",
                headers={"X-API-KEY": API_KEY, "Content-Type": "application/json"},
            )
            resp.raise_for_status()
            raw = resp.json()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                raise HTTPException(status_code=404, detail=f"Request ID '{request_id}' not found.")
            raise HTTPException(status_code=502, detail=f"RD API error: {exc.response.status_code}")
        except Exception as exc:
            raise HTTPException(status_code=502, detail=str(exc))

    score, st     = rd_client.parse_score_and_status(raw)
    elapsed       = int((time.time() - t_start) * 1000)
    media_type_rd = (raw.get("mediaType") or "UNKNOWN").upper()

    return AnalyzeResponse(
        success            = True,
        status             = st,
        score              = round(score, 2),
        confidence         = rd_client.score_to_confidence(score),
        media_type         = media_type_rd,
        request_id         = request_id,
        filename           = raw.get("originalFileName") or raw.get("filename") or "unknown",
        file_size_bytes    = 0,
        processing_time_ms = elapsed,
        analyzed_at        = datetime.utcnow().isoformat() + "Z",
        models             = _build_models(raw),
        rd_raw             = raw if debug else None,
    )


# ── Global exception handler ─────────────────────────────────────────────────
@app.exception_handler(Exception)
async def generic_exception_handler(request, exc):
    logger.exception("Unhandled exception: %s", exc)
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error"  : "Internal server error",
            "detail" : str(exc),
        },
    )
