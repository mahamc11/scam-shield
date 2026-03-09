# Scam Shield – AI Recruitment Fraud Detection Platform

Scam Shield is a Flask-based web app that helps job seekers evaluate suspicious recruiter messages and job offers.

## Features
- Modern landing page with product overview and usage steps.
- User registration/login and session-based dashboard access.
- Scam detection form with:
  - Company name and address
  - Description + microphone speech-to-text input
  - Phone number verification checks
  - Evidence uploads (audio/images/documents)
- AI-style heuristic analysis combining text, phone, company verification, and evidence signals.
- Simulated company existence checks using LinkedIn, Google Maps, and Glassdoor indicators.
- Result label (`Scam`, `Suspicious`, `Likely Genuine`) + score + explanations.
- Analytics charts (Chart.js): scam probability, risk factors, and verification status.
- Sidebar chatbot with anti-scam advice.

## Architecture
- **Backend (Flask, `app.py`)**
  - Routes for landing, auth, dashboard, detection, and chatbot APIs.
  - SQLite database stores users and detection history metadata.
  - Detection pipeline:
    1. Merge text + voice transcript.
    2. Translate to English (auto detect) when translator dependency is available.
    3. Score text risk via keyword-based NLP heuristics.
    4. Score phone number via pattern + known reported list.
    5. Simulate company verification status.
    6. Persist and render results.
- **Frontend (Jinja + JS + CSS)**
  - Responsive UI and forms.
  - Web Speech API for speech-to-text capture.
  - Fetch-based chatbot client.
  - Chart.js visualization for analysis results.

## Run locally
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open: `http://localhost:5000`

## Notes
- Voice input uses browser-native Web Speech API support.
- Translation uses `deep-translator` when available; otherwise app falls back to original text.
