# PhishGuard Command Center

PhishGuard is a commercial-grade phishing detection platform built with Flask, Python, machine learning, HTML, CSS, and JavaScript. The project has been upgraded from a prototype into a modular cybersecurity SaaS foundation with authentication, database-backed history, reports, email analysis, bulk scanning, admin APIs, Docker deployment, and mobile-ready REST endpoints.

## Abstract

Phishing remains one of the most common attack vectors against users and organizations. PhishGuard analyzes URLs and email content using explainable rules, ML scoring, SSL verification, redirect checks, domain intelligence, brand impersonation detection, and reputation signals. The system provides clear Safe, Suspicious, and Phishing verdicts with risk scores, findings, and recommended actions.

## Problem Statement

Users often cannot identify malicious URLs before clicking them, and many academic phishing projects stop at a basic ML prediction. A practical cybersecurity product needs secure APIs, auditability, history, analytics, reporting, mobile readiness, and extensible architecture.

## Objectives

- Provide a secure Flask backend with modular routes, services, database, auth, and utilities.
- Detect suspicious URLs with explainable AI output and ML-assisted scoring.
- Store scan history, reports, analytics, and users in SQLite for development.
- Prepare PostgreSQL-compatible deployment through `DATABASE_URL` conventions.
- Expose versioned APIs for Flutter Android apps and Chrome extensions.
- Provide a professional command-center UI for URL, email, and bulk analysis.

## Architecture

```text
Browser / Flutter / Chrome Extension
        |
        v
Flask API Layer
  routes/auth_routes.py
  routes/scan.py
  routes/history.py
  routes/reports.py
  routes/admin.py
        |
        v
Services Layer
  ScanService
  ReportService
  EmailAnalyzer
  Model Performance Service
        |
        v
Detection Engine + Database
  detector.py
  database.py
  SQLite / future PostgreSQL
```

## Modules

- `app.py`: application factory, security headers, CORS, service registration, web routes, error handling.
- `config.py`: environment-based configuration.
- `database.py`: SQLite connection, schema, transactions, JSON helpers.
- `auth.py`: password hashing, signed bearer tokens, auth/admin decorators.
- `detector.py`: phishing detection engine.
- `routes/`: API route layer.
- `services/`: business logic layer.
- `utils/`: validation and response helpers.
- `templates/index.html`: command-center dashboard.
- `static/css/style.css`: commercial cybersecurity UI.
- `static/js/script.js`: frontend API client and interactive modules.
- `tests/test_api.py`: API and detection smoke tests.

## Features

- URL validation and normalization
- Suspicious keyword, character, entropy, and length checks
- Brand impersonation detection
- URL shortener detection
- IP address URL detection
- Suspicious TLD detection
- Redirect chain analysis
- HTTPS and SSL certificate verification
- RDAP domain age, registrar, and country lookup
- Local blacklist and optional Google Safe Browsing
- Email phishing analyzer
- Bulk URL scanner
- Database-backed scan history
- Searchable history and analytics
- PDF security reports
- Registration and login with bearer token
- Admin overview endpoint
- Model performance dashboard payload
- Docker, Render, Railway, and VPS readiness

## API Documentation

### Health

```http
GET /api/v1/health
```

### Authentication

```http
POST /api/v1/auth/register
POST /api/v1/auth/login
```

Body:

```json
{
  "name": "Analyst",
  "email": "analyst@example.com",
  "password": "Password123"
}
```

Use returned token:

```http
Authorization: Bearer <token>
```

### URL Scan

```http
POST /api/v1/scan
Content-Type: application/json

{
  "url": "https://google.com@secure-login-google.com/verify/account"
}
```

### History and Analytics

```http
GET /api/v1/history
GET /api/v1/history?q=paypal
GET /api/v1/history/analytics
```

### Reports

```http
POST /api/v1/reports
POST /api/v1/reports/pdf
```

### Email Analyzer

```http
POST /api/v1/email/analyze
```

### Bulk Scanner

```http
POST /api/v1/bulk-scan
```

### Admin

```http
GET /api/v1/admin/overview
```

Requires an authenticated user with role `admin`.

## Database Design

- `users`: account identity, password hash, role, email verification status.
- `scans`: scanned URL, verdict, score, confidence, JSON result, user ownership.
- `reports`: generated reports linked to scans and users.
- `audit_logs`: security and user activity events.

## Setup

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python app.py
```

Open `http://127.0.0.1:5000`.

## Testing

```powershell
pytest
```

## Docker

```bash
docker build -t phishguard .
docker run -p 8000:8000 --env SECRET_KEY=change-me phishguard
```

Or:

```bash
docker compose up --build
```

## Deployment

### Render

- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --threads 4 --timeout 120`
- Add variables from `.env.example`.

### Railway

- Connect the repository.
- Railway uses the `Procfile`.
- Add environment variables.

### VPS/Linux

```bash
python3.12 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="replace-with-random-secret"
gunicorn app:app --bind 0.0.0.0:8000 --workers 2 --threads 4
```

Use Nginx or Caddy in front of Gunicorn for TLS and reverse proxying.

## Future Scope

- PostgreSQL adapter and migrations.
- Full email verification and password reset delivery.
- QR image extraction with OpenCV or pyzbar.
- Chrome extension package.
- Flutter app using `/api/v1/*`.
- Threat feed integrations such as PhishTank, OpenPhish, and enterprise blocklists.
- Background URL monitoring and alerting.
- SIEM/SOAR integrations.

## Conclusion

PhishGuard is now organized as a professional cybersecurity platform foundation. It includes modular backend architecture, secure API patterns, database persistence, report generation, analytics, an upgraded command-center UI, deployment artifacts, and test scaffolding.
