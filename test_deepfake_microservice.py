import cv2
import numpy as np
import httpx

# 1. Create a dummy test image
img = np.zeros((100, 100, 3), dtype=np.uint8)
img[:] = (0, 0, 255) # Red image
cv2.imwrite('test_image.jpg', img)

print("Created test_image.jpg")

# 2. Test the deepfake microservice directly
url = "http://localhost:8001/analyze/image"
print(f"Testing Microservice directly at {url}...")

with open('test_image.jpg', 'rb') as f:
    # Use httpx to post the file
    response = httpx.post(url, files={'file': ('test_image.jpg', f, 'image/jpeg')}, timeout=30.0)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")

