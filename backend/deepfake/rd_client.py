"""
rd_client.py
Async Reality Defender API client — handles presign, upload, polling.
"""

import asyncio
import logging
import httpx

logger = logging.getLogger("rd_client")

RD_BASE_URL    = "https://api.prd.realitydefender.xyz"
MAX_POLL       = 60
POLL_INTERVAL  = 3   # seconds


def _rd_headers(api_key: str) -> dict:
    return {"X-API-KEY": api_key, "Content-Type": "application/json"}


async def get_presigned_url(api_key: str, filename: str) -> dict:
    """Request a pre-signed S3 upload URL from Reality Defender."""
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{RD_BASE_URL}/api/files/aws-presigned",
            headers=_rd_headers(api_key),
            json={"fileName": filename},
        )
        resp.raise_for_status()
        return resp.json()


async def upload_to_presigned(signed_url: str, file_bytes: bytes) -> None:
    """PUT file bytes to the S3 pre-signed URL."""
    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.put(
            signed_url,
            content=file_bytes,
            headers={"Content-Type": "application/octet-stream"},
        )
        resp.raise_for_status()


async def poll_result(api_key: str, request_id: str) -> dict | None:
    """
    Poll /api/media/users/{request_id} until a terminal status is returned
    or MAX_POLL attempts are exhausted.
    Returns the full result dict or None on timeout.
    """
    terminal = {"AUTHENTIC", "FAKE", "SUSPICIOUS", "NOT_APPLICABLE", "UNABLE_TO_EVALUATE"}

    async with httpx.AsyncClient(timeout=20) as client:
        for attempt in range(1, MAX_POLL + 1):
            try:
                resp = await client.get(
                    f"{RD_BASE_URL}/api/media/users/{request_id}",
                    headers=_rd_headers(api_key),
                )
                resp.raise_for_status()
                data    = resp.json()
                summary = data.get("resultsSummary") or data.get("result_summary") or {}
                status  = (summary.get("status") or data.get("status") or "").upper()

                logger.info("Poll attempt %d/%d — request_id=%s status=%s",
                            attempt, MAX_POLL, request_id, status or "PROCESSING")

                if status in terminal:
                    return data

            except httpx.HTTPStatusError as exc:
                logger.warning("Poll HTTP error attempt %d: %s", attempt, exc)
            except Exception as exc:
                logger.warning("Poll error attempt %d: %s", attempt, exc)

            await asyncio.sleep(POLL_INTERVAL)

    logger.error("Poll timed out for request_id=%s", request_id)
    return None


def parse_presign_response(presign: dict) -> tuple[str, str]:
    """
    Extract (signed_url, request_id) from the presign response.
    Handles nested { "response": { "signedUrl": "..." } } structure.
    """
    nested = presign.get("response") or {}

    signed_url = (
        nested.get("signedUrl") or nested.get("url")
        or presign.get("signedUrl") or presign.get("url")
        or presign.get("signed_url") or presign.get("uploadUrl")
    )
    request_id = (
        presign.get("requestId") or presign.get("mediaId")
        or presign.get("request_id") or presign.get("id")
        or nested.get("requestId") or nested.get("mediaId")
    )

    return signed_url, request_id


async def analyze_file(
    api_key:    str,
    file_bytes: bytes,
    filename:   str,
) -> dict | None:
    """
    Full single-file pipeline:
      1. Get presigned URL
      2. Upload file
      3. Poll until result ready
    Returns the raw RD result dict or None on failure.
    Raises httpx.HTTPStatusError on API errors.
    """
    presign    = await get_presigned_url(api_key, filename)
    signed_url, request_id = parse_presign_response(presign)

    if not signed_url:
        raise ValueError(f"No signed URL in presign response: {presign}")
    if not request_id:
        raise ValueError(f"No request_id in presign response: {presign}")

    await upload_to_presigned(signed_url, file_bytes)
    result = await poll_result(api_key, request_id)
    return result


def parse_score_and_status(result: dict) -> tuple[float, str]:
    """Return (score 0-100, STATUS_STRING) from a raw RD result."""
    summary = result.get("resultsSummary") or result.get("result_summary") or {}
    status  = (summary.get("status") or result.get("status") or "UNKNOWN").upper()
    meta    = summary.get("metadata") or {}
    raw     = (meta.get("finalScore") or meta.get("final_score")
               or meta.get("score") or 0)
    score   = float(raw)
    score   = score * 100 if score <= 1 else score
    return min(max(score, 0.0), 100.0), status


def score_to_confidence(score: float) -> str:
    if score >= 70 or score <= 30:
        return "HIGH"
    if score >= 55 or score <= 45:
        return "MEDIUM"
    return "LOW"
