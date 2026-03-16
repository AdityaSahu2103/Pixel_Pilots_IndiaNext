# DeepShield FastAPI Backend

Deepfake detection API powered by Reality Defender — Free Tier compatible.

## Setup

```bash
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Docs auto-generated at: http://localhost:8000/docs

---

## Endpoints

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/` | Health check + API connectivity |
| POST | `/analyze/image` | Analyze image for deepfake |
| POST | `/analyze/audio` | Analyze audio for AI voice |
| POST | `/analyze/video` | Analyze video (frame + audio pipeline) |
| GET | `/result/{request_id}` | Fetch result by RD request ID |

### Query params (all analyze endpoints)
- `?debug=true` — include full raw RD API response in output

### Video-specific
- `?n_frames=5` — number of key frames to extract (1–10, default 5)

---

## Response Shape

```json
{
  "success": true,
  "status": "FAKE",
  "score": 87.4,
  "confidence": "HIGH",
  "media_type": "IMAGE",
  "request_id": "uuid",
  "filename": "photo.jpg",
  "file_size_bytes": 204800,
  "processing_time_ms": 4200,
  "analyzed_at": "2026-03-17T12:00:00Z",
  "models": [
    { "name": "ModelA", "score": 88.1 }
  ],

  // Video only:
  "frame_scores":   [72.1, 85.3, 90.0, 88.5, 76.2],
  "frame_statuses": ["SUSPICIOUS", "FAKE", "FAKE", "FAKE", "SUSPICIOUS"],
  "audio_score":    45.2,
  "audio_status":   "SUSPICIOUS",
  "mean_score":     82.4,
  "peak_score":     90.0,
  "video_metadata": { "fps": 30, "duration_s": 12.5, "width": 1280, "height": 720 },

  "error": null
}
```

---

## Next.js Integration Examples

### Image Upload

```typescript
// lib/deepfake.ts

const API_BASE = process.env.NEXT_PUBLIC_DEEPFAKE_API ?? "http://localhost:8000";

export interface DeepfakeResult {
  success: boolean;
  status: "FAKE" | "AUTHENTIC" | "SUSPICIOUS" | "NOT_APPLICABLE" | "UNABLE_TO_EVALUATE" | "ERROR";
  score: number;
  confidence: "HIGH" | "MEDIUM" | "LOW";
  media_type: string;
  request_id?: string;
  filename: string;
  processing_time_ms: number;
  analyzed_at: string;
  models: { name: string; score: number }[];
  frame_scores?: number[];
  frame_statuses?: string[];
  audio_score?: number;
  audio_status?: string;
  mean_score?: number;
  peak_score?: number;
  video_metadata?: Record<string, unknown>;
  error?: string;
}

export async function analyzeImage(file: File): Promise<DeepfakeResult> {
  const form = new FormData();
  form.append("file", file);

  const res = await fetch(`${API_BASE}/analyze/image`, {
    method: "POST",
    body: form,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail ?? `HTTP ${res.status}`);
  }
  return res.json();
}

export async function analyzeAudio(file: File): Promise<DeepfakeResult> {
  const form = new FormData();
  form.append("file", file);

  const res = await fetch(`${API_BASE}/analyze/audio`, {
    method: "POST",
    body: form,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail ?? `HTTP ${res.status}`);
  }
  return res.json();
}

export async function analyzeVideo(
  file: File,
  nFrames: number = 5
): Promise<DeepfakeResult> {
  const form = new FormData();
  form.append("file", file);

  const res = await fetch(`${API_BASE}/analyze/video?n_frames=${nFrames}`, {
    method: "POST",
    body: form,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail ?? `HTTP ${res.status}`);
  }
  return res.json();
}

export async function getResult(requestId: string): Promise<DeepfakeResult> {
  const res = await fetch(`${API_BASE}/result/${requestId}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail ?? `HTTP ${res.status}`);
  }
  return res.json();
}
```

### React Component Example

```tsx
// components/DeepfakeUploader.tsx
"use client";

import { useState } from "react";
import { analyzeImage, DeepfakeResult } from "@/lib/deepfake";

export default function DeepfakeUploader() {
  const [result, setResult]   = useState<DeepfakeResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState<string | null>(null);

  async function handleFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await analyzeImage(file);
      setResult(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  const statusColor = {
    FAKE:       "text-red-500",
    AUTHENTIC:  "text-green-500",
    SUSPICIOUS: "text-yellow-500",
  }[result?.status ?? ""] ?? "text-gray-400";

  return (
    <div className="p-6 max-w-lg mx-auto">
      <input type="file" accept="image/*" onChange={handleFile} />

      {loading && <p className="mt-4 text-blue-400">Analyzing...</p>}

      {error && <p className="mt-4 text-red-500">{error}</p>}

      {result && (
        <div className="mt-4 p-4 border rounded-lg">
          <p className={`text-2xl font-bold ${statusColor}`}>
            {result.status}
          </p>
          <p className="text-gray-300">
            Score: <strong>{result.score.toFixed(1)}</strong> / 100
          </p>
          <p className="text-gray-400 text-sm">
            Confidence: {result.confidence} · {result.processing_time_ms}ms
          </p>
        </div>
      )}
    </div>
  );
}
```

### Next.js API Route (server-side proxy — hides API key)

```typescript
// app/api/analyze/route.ts
import { NextRequest, NextResponse } from "next/server";

const API_BASE = process.env.DEEPFAKE_API_INTERNAL ?? "http://localhost:8000";

export async function POST(req: NextRequest) {
  const formData = await req.formData();
  const type     = req.nextUrl.searchParams.get("type") ?? "image";

  const res = await fetch(`${API_BASE}/analyze/${type}`, {
    method: "POST",
    body  : formData,
  });

  const data = await res.json();
  return NextResponse.json(data, { status: res.status });
}
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RD_API_KEY` | hardcoded | Reality Defender API key |
| `NUM_FRAMES` | `5` | Default frames for video analysis |

Set via `.env` or export before running:
```bash
set RD_API_KEY=rd_your_key_here   # Windows
uvicorn main:app --reload --port 8000
```
