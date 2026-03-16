import asyncio
import httpx
import json

async def test_video():
    url = "http://localhost:8001/analyze/video"
    print(f"Testing Deepfake Video endpoint: {url}")
    
    # Just send dummy bytes as video
    dummy_video_bytes = b"dummy video content"
    files = {"file": ("test_video.mp4", dummy_video_bytes, "video/mp4")}
    
    async with httpx.AsyncClient(timeout=120.0) as client:
        try:
            resp = await client.post(url, files=files)
            print("Status Code:", resp.status_code)
            try:
                print("Response Body:", json.dumps(resp.json(), indent=2))
            except:
                print("Raw Text:", resp.text)
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(test_video())
