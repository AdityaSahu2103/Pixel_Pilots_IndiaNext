"""
video_utils.py
Frame extraction (OpenCV) and audio extraction (ffmpeg subprocess).
"""

import asyncio
import logging
import os
import subprocess
import tempfile

import cv2
import numpy as np

logger = logging.getLogger("video_utils")


# ─── FRAME EXTRACTION ────────────────────────────────────────────────────────

def extract_key_frames(video_path: str, n: int = 5) -> list[tuple[int, np.ndarray]]:
    """
    Extract n evenly-spaced key frames from a video file.
    Returns list of (frame_index, frame_bgr_ndarray).
    """
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        logger.error("Cannot open video: %s", video_path)
        return []

    total   = max(int(cap.get(cv2.CAP_PROP_FRAME_COUNT)), 1)
    indices = [int(i * (total - 1) / max(n - 1, 1)) for i in range(n)]

    frames = []
    for idx in indices:
        cap.set(cv2.CAP_PROP_POS_FRAMES, idx)
        ret, frame = cap.read()
        if ret and frame is not None:
            frames.append((idx, frame))
        else:
            logger.warning("Could not read frame at index %d", idx)

    cap.release()
    logger.info("Extracted %d/%d frames from %s", len(frames), n, video_path)
    return frames


def encode_frame_jpeg(frame_bgr: np.ndarray, quality: int = 92) -> bytes:
    """Encode an OpenCV BGR frame as JPEG bytes."""
    ok, buf = cv2.imencode(
        ".jpg", frame_bgr,
        [cv2.IMWRITE_JPEG_QUALITY, quality]
    )
    if not ok:
        raise RuntimeError("Failed to encode frame as JPEG")
    return buf.tobytes()


def get_video_metadata(video_path: str) -> dict:
    """Return basic video metadata (fps, total frames, width, height, duration_s)."""
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        return {}

    fps     = cap.get(cv2.CAP_PROP_FPS) or 0
    total   = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    width   = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height  = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    dur     = (total / fps) if fps > 0 else 0
    cap.release()

    return {
        "fps"        : round(fps, 2),
        "frame_count": total,
        "width"      : width,
        "height"     : height,
        "duration_s" : round(dur, 2),
    }


# ─── AUDIO EXTRACTION ────────────────────────────────────────────────────────

def ffmpeg_available() -> bool:
    """Check whether ffmpeg is installed and on PATH."""
    try:
        r = subprocess.run(
            ["ffmpeg", "-version"],
            capture_output=True, timeout=5
        )
        return r.returncode == 0
    except Exception:
        return False


def extract_audio(video_path: str, output_path: str) -> bool:
    """
    Extract audio track from video as 16-kHz mono WAV using ffmpeg.
    Returns True on success, False if ffmpeg is unavailable or no audio track.
    """
    if not ffmpeg_available():
        logger.warning("ffmpeg not found — skipping audio extraction")
        return False

    try:
        result = subprocess.run(
            [
                "ffmpeg", "-y",
                "-i", video_path,
                "-vn",
                "-acodec", "pcm_s16le",
                "-ar", "16000",
                "-ac", "1",
                output_path,
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        success = os.path.exists(output_path) and os.path.getsize(output_path) > 1024
        if not success:
            logger.warning("ffmpeg ran but output is empty/missing. stderr: %s",
                           result.stderr[-300:])
        return success

    except subprocess.TimeoutExpired:
        logger.error("ffmpeg timed out for %s", video_path)
        return False
    except Exception as exc:
        logger.error("ffmpeg error: %s", exc)
        return False


# ─── ASYNC WRAPPERS ──────────────────────────────────────────────────────────

async def extract_key_frames_async(
    video_path: str, n: int = 5
) -> list[tuple[int, np.ndarray]]:
    """Run extract_key_frames in a thread so it doesn't block the event loop."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, extract_key_frames, video_path, n)


async def extract_audio_async(video_path: str, output_path: str) -> bool:
    """Run extract_audio in a thread so it doesn't block the event loop."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, extract_audio, video_path, output_path)
