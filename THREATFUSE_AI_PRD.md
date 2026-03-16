# 1. Project Vision

ThreatFuse AI is an **Agentic Cybersecurity Platform** designed to detect, analyze, explain, and mitigate modern AI-powered cyber threats in real time.

The system combines:

- Multi-agent AI architecture
- Threat intelligence APIs
- Local machine learning validation
- Explainable AI
- Automated mitigation playbooks
- Visual threat analysis dashboard

The goal is to **convert raw threat alerts into understandable security intelligence.**

---

# 2. Development Rules (MANDATORY)

The system must follow these development rules strictly.

## Rule 1 — Latest Libraries Only

Use only **latest stable versions** of libraries to avoid deprecated APIs.

Examples:

Backend

Python 3.11+
FastAPI
Pydantic v2
Async HTTPX
SQLAlchemy 2.x
Redis 7+

Frontend

React 18+
TypeScript
Vite
TailwindCSS
Radix UI
Framer Motion

Security

JWT authentication
Rate limiting
CORS protection

---

## Rule 2 — Award-Winning UI Design

The UI must resemble **top-tier cybersecurity platforms** such as:

CrowdStrike  
Palantir  
Snyk  
Datadog  

Design requirements:

Dark cybersecurity theme  
Glassmorphism  
Neon accents  
Animated agent nodes  
Smooth transitions  
Responsive dashboard  

Color Palette

Primary: #38BDF8  
Danger: #EF4444  
Warning: #F59E0B  
Success: #10B981  
Background: #0F172A  

---

## Rule 3 — Test Before Expanding

Development must follow this strict cycle:

1. Implement feature
2. Test functionality
3. Confirm working
4. Ask user to continue
5. Implement next feature

No feature expansion without testing confirmation.

---

# 3. Problem Statement

Modern cybersecurity systems suffer from:

- Black-box threat alerts
- Siloed detection tools
- High false positive rates
- Lack of explainability
- Slow investigation workflows

Organizations waste massive time analyzing alerts that provide no context.

ThreatFuse AI solves this by providing:

- Multi-threat detection
- Explainable threat evidence
- Visual attack timelines
- Actionable mitigation playbooks

---

# 4. Target Users

Primary Users

Security Operations Teams  
Small and Medium Businesses  
Government Agencies  
Individual Users  

Use Cases

Phishing detection  
Malicious URL scanning  
Prompt injection detection  
Deepfake verification  
User behavior anomaly detection  

---

# 5. Key Differentiators

ThreatFuse AI introduces several unique features.

## Multi-Agent Architecture

Specialized agents collaborate to analyze threats.

## Threat Breadcrumbs

A visual timeline explaining **how a threat was detected.**

Example

13:45:22 — URGENT keyword detected  
13:45:23 — suspicious domain detected  
13:45:24 — sender mismatch  

## Unified Threat Dashboard

One platform detects multiple attack types.

## Explainable AI

Clear explanations of why threats were flagged.

## Automated Mitigation

Risk-based response playbooks.

---

# 6. System Architecture

The platform uses a **5-agent architecture**.


User Input
│
▼
Agent 1: Orchestrator
(Input routing)
│
▼
Agent 2: Network Scraper
(Threat intelligence APIs)
│
▼
Agent 3: Semantic Analyst
(Local ML validation)
│
▼
Agent 4: Explainer
(RAG + visual breadcrumbs)
│
▼
Agent 5: Mitigation Expert
(Security playbooks)
│
▼
Dashboard + API


---

# 7. Agent Specifications

## Agent 1 — Orchestrator

Responsibilities

Input detection  
Routing pipeline  
Threat classification  

Example logic


if url detected → URL pipeline
if email content → phishing pipeline
if video file → deepfake pipeline


---

## Agent 2 — Network Scraper

Collects threat intelligence.

Sources

VirusTotal  
PhishTank  
Reality Defender  
SafePrompt  

Outputs normalized JSON threat scores.

---

## Agent 3 — Semantic Analyst

Local ML validation layer.

Purpose

Reduce false positives  
Analyze linguistic patterns  
Detect social engineering tactics  

Tech

TF-IDF / Transformer classifier  
Isolation Forest for anomalies

---

## Agent 4 — Explainer

Creates human-readable explanations.

Functions

Generate threat evidence  
Create breadcrumb timeline  
Highlight suspicious content

---

## Agent 5 — Mitigation Expert

Creates response recommendations.

Example

Risk > 80

Action: QUARANTINE  
Priority: CRITICAL

Risk 40–80

Action: REVIEW

Risk < 40

Action: MONITOR

---

# 8. UI Dashboard Requirements

The dashboard must include:

## Threat Input Console

Paste email / URL / prompt / upload file.

## Agent Pipeline Visualization

Animated pipeline showing:

Input Agent  
Detection Agent  
Validation Agent  
Explainer Agent  
Mitigation Agent

## Threat Breadcrumbs Panel

Visual timeline explaining threat detection.

## Evidence Highlights

Highlight suspicious words.

## Risk Score

Animated risk meter.

## Recommended Actions

Quarantine  
Report  
Audit  

---

# 9. Technical Stack

Backend

FastAPI  
Python 3.11  
Docker  
Redis  
PostgreSQL  

Frontend

React  
TypeScript  
TailwindCSS  
Framer Motion  

AI

HuggingFace models  
Isolation Forest  
RAG explainability pipeline  

---

# 10. API Endpoints

POST /analyze

Input


{
"input": "URGENT: Click http://bank-login.xyz
",
"input_type": "email"
}


Output


{
"risk_score": 78,
"confidence": 92,
"breadcrumbs": [...],
"action": "QUARANTINE"
}


---

# 11. Development Workflow

The system must be implemented in stages.

Stage 1

Backend setup  
FastAPI server  

Stage 2

Orchestrator agent

Stage 3

Threat detection APIs

Stage 4

Semantic ML validation

Stage 5

Explainability engine

Stage 6

Mitigation engine

Stage 7

Frontend dashboard

Stage 8

Integration testing

Each stage must be tested before continuing.

---

# 12. Testing Strategy

Unit Tests

Agent routing  
API response parsing  
ML validation  

Integration Tests

Email → phishing detection  
URL → malicious detection  
Prompt → injection detection  

Performance Tests

End-to-end analysis < 3 seconds

---

# 13. Deployment

Local

Docker Compose

Production

Backend → Render  
Frontend → Vercel  

---

# 14. Success Metrics

Hackathon Goals

Functional demo  
Stable system  
Clear explanations  
Fast response  

Product Goals

High accuracy  
Low false positives  
Easy user understanding

---

# 15. Context Prompt for Antigravity (Claude Opus 4.6)

You are building a production-ready cybersecurity platform called **ThreatFuse AI**.

Your task is to implement a **fully functional system** following the PRD above.

Strict requirements:

1. Use only modern, non-deprecated libraries.
2. Build an award-winning cybersecurity dashboard UI.
3. Implement the system step-by-step.
4. After implementing each feature, test it.
5. Ask the user to confirm before proceeding to the next stage.
6. Ensure the system is production-ready.
7. Maintain clean modular architecture.
8. Use proper logging and error handling.

The final system must include:

- 5-agent architecture
- threat detection APIs
- ML validation
- explainable threat breadcrumbs
- automated mitigation
- real-time dashboard

Do not skip testing steps.

Always confirm functionality before moving forward.

Begin with **Stage 1: Backend initialization and project structure.**