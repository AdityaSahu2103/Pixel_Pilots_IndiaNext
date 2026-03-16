import email
import json
import httpx
from email.message import EmailMessage

# 1. Create a dummy image
import cv2
import numpy as np
img = np.zeros((100, 100, 3), dtype=np.uint8)
img[:] = (0, 0, 255) # Red image
cv2.imwrite('fake_attachment.jpg', img)

with open('fake_attachment.jpg', 'rb') as f:
    img_data = f.read()

# 2. Build a raw MIME email
msg = EmailMessage()
msg['Subject'] = 'Here is the video you requested'
msg['From'] = 'hacker@scam.com'
msg['To'] = 'victim@company.com'
msg.set_content('Please check the attached deepfake video proof.\n\nThanks.')

msg.add_attachment(img_data, maintype='image', subtype='jpeg', filename='fake_attachment.jpg')

raw_email_str = msg.as_string()

# 3. Send to our main Backend pipeline
url = "http://localhost:8000/api/analyze/email"
payload = {
    "raw_email": raw_email_str,
    "sender": "hacker@scam.com",
    "subject": "Here is the video you requested"
}

print("Submitting email with attachment to Main Backend...")

# Increased timeout to allow 7 agents + microservice to finish
try:
    response = httpx.post(url, json=payload, timeout=120.0)
    print(f"Status Code: {response.status_code}")
    
    data = response.json()
    
    # Check if deepfake was detected
    detections = data.get("detections", [])
    deepfake_det = next((d for d in detections if d["threat_type"] == "deepfake"), None)
    
    if deepfake_det:
        print("\n✅ DEEPFAKE PIPELINE WORKED!")
        print(f"Confidence: {deepfake_det['confidence']}")
        print(f"Evidence: {deepfake_det['evidence']}")
    else:
        print("\n❌ Deepfake was NOT triggered.")
        print(json.dumps(data, indent=2))
        
except Exception as e:
    print(f"\n❌ Error during pipeline test: {e}")
