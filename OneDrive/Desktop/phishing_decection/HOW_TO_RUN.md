# How To Run PhishGuard

This guide explains how to run the PhishGuard project locally and with Docker.

## 1. Open The Project Folder

```powershell
cd C:\Users\xhasi\OneDrive\Desktop\phishing_decection
```

## 2. Create A Virtual Environment

```powershell
python -m venv venv
```

Activate it:

```powershell
.\venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
```

## 3. Install Requirements

```powershell
pip install -r requirements.txt
```

## 4. Create Environment File

Copy the example file:

```powershell
Copy-Item .env.example .env
```

Open `.env` and change at least:

```env
SECRET_KEY=replace-this-with-a-long-random-secret
```

Google Safe Browsing is optional:

```env
GOOGLE_SAFE_BROWSING_API_KEY=
```

## 5. Run The Project

```powershell
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

You should see the **PhishGuard Command Center** dashboard.

## 6. Test The API

Health check:

```powershell
Invoke-WebRequest http://127.0.0.1:5000/api/v1/health -UseBasicParsing
```

Scan a sample phishing URL:

```powershell
Invoke-WebRequest `
  -Uri http://127.0.0.1:5000/api/v1/scan `
  -Method POST `
  -ContentType "application/json" `
  -Body '{"url":"https://google.com@secure-login-google.com/verify/account"}' `
  -UseBasicParsing
```

## 7. Run Tests

Install requirements first, then run:

```powershell
pytest
```

If `pytest` is not recognized:

```powershell
python -m pytest
```

## 8. Run With Docker

Build the image:

```powershell
docker build -t phishguard .
```

Run the container:

```powershell
docker run -p 8000:8000 -e SECRET_KEY=replace-this-secret phishguard
```

Open:

```text
http://127.0.0.1:8000
```

## 9. Run With Docker Compose

```powershell
docker compose up --build
```

Open:

```text
http://127.0.0.1:8000
```

## 10. Production Command

For Render, Railway, VPS, or Linux server:

```bash
gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --threads 4 --timeout 120
```

For a VPS without `$PORT`:

```bash
gunicorn app:app --bind 0.0.0.0:8000 --workers 2 --threads 4 --timeout 120
```

## 11. Main API Endpoints

```text
GET  /api/v1/health
POST /api/v1/auth/register
POST /api/v1/auth/login
POST /api/v1/auth/logout
POST /api/v1/scan
GET  /api/v1/history
GET  /api/v1/history/analytics
POST /api/v1/reports
GET  /api/v1/reports/{id}
POST /api/v1/reports/pdf
POST /api/v1/email/analyze
POST /api/v1/bulk-scan
GET  /api/v1/model/performance
GET  /api/v1/admin/overview
```

## 12. Common Problems

### Page Does Not Show New Design

Press:

```text
Ctrl + F5
```

This forces the browser to reload CSS and JavaScript.

### Port 5000 Already In Use

Run with another port:

```powershell
$env:PORT=5050
python app.py
```

Then open:

```text
http://127.0.0.1:5050
```

### Missing Packages

Run:

```powershell
pip install -r requirements.txt
```

### Database File

The local SQLite database is created automatically at:

```text
instance/phishguard.db
```

