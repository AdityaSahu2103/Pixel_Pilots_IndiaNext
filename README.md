# CyberShield AI 🛡️

> **Multi-Agent Cyber Defense Platform** — Detects, analyzes, and explains emerging cyber threats using AI/ML techniques.

Built for **IndiaNext Hackathon 2026** by Team Pixel Pilots.

## 🎯 What It Does

CyberShield AI is an intelligent cybersecurity platform that processes emails, URLs, messages, and files to detect multiple threat types simultaneously:

- 🎣 **Phishing Detection** — Email header analysis + Google Safe Browsing API
- 🔗 **Malicious URL Scanning** — VirusTotal API integration
- 🎭 **Deepfake Detection** — Reality Defender API
- 💉 **Prompt Injection Detection** — Pattern matching + LLM scoring
- 📊 **Anomaly Detection** — ML-based behavior analysis (IsolationForest)
- 🤖 **Explainable AI** — LLM-powered explanations with evidence breadcrumbs
- 🧪 **Adversarial Robustness Testing** — Input mutation + rescan

## 🏗️ Architecture

Multi-agent system with parallel detection, cross-validation, and LLM-powered explainability.

```
Input → Content Extractor → Parallel Detection Agents → Cross-Validator → LLM Explainer → Visual Breadcrumbs
```

## 🚀 Quick Start

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
.\venv\Scripts\activate   # Windows

# Install dependencies
pip install -r backend/requirements.txt

# Configure API keys
cp .env.example .env
# Edit .env with your API keys

# Run the server
uvicorn backend.main:app --reload --port 8000
```

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | System health check |
| `POST` | `/api/analyze` | Main threat scan (auto-detect input type) |
| `POST` | `/api/analyze/email` | Email-specific scan |
| `POST` | `/api/analyze/url` | URL-specific scan |
| `POST` | `/api/analyze/text` | Text/message scan |
| `GET` | `/api/reports/{scan_id}` | Fetch scan report |
| `POST` | `/api/reports/{scan_id}/adversarial` | Adversarial robustness test |

## 🧑‍💻 Tech Stack

- **Backend**: FastAPI + Python 3.12
- **AI/ML**: scikit-learn, Groq (LLaMA 3.3 70B)
- **APIs**: VirusTotal, Google Safe Browsing, Reality Defender
- **Frontend**: Progressive Web App (Next.js) — *coming soon*

## 📁 Project Structure

```
├── backend/
│   ├── main.py              # FastAPI entry point
│   ├── config.py            # Configuration
│   ├── agents/              # Detection agents
│   ├── llm/                 # LLM explainer layer
│   ├── models/              # Pydantic schemas
│   ├── services/            # Business logic services
│   └── routers/             # API routes
├── frontend/                # PWA (Phase 2)
└── docs/                    # Documentation
```

## 📄 License

Built for IndiaNext Hackathon 2026. All rights reserved.
