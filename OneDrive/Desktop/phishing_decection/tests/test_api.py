from app import app


def test_health_endpoint():
    client = app.test_client()
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "healthy"


def test_scan_rejects_script_scheme():
    client = app.test_client()
    response = client.post("/api/v1/scan", json={"url": "javascript:alert(1)"})
    assert response.status_code == 400
    assert response.get_json()["success"] is False


def test_phishing_sample_scores_high():
    client = app.test_client()
    response = client.post("/api/v1/scan", json={"url": "https://google.com@secure-login-google.com/verify/account"})
    assert response.status_code == 200
    data = response.get_json()["data"]
    assert data["status"] == "phishing"
    assert data["risk_score"] >= 60


def test_report_pdf_endpoint():
    client = app.test_client()
    response = client.post("/api/v1/reports/pdf", json={"url": "https://google.com@secure-login-google.com/verify/account"})
    assert response.status_code == 200
    assert response.data.startswith(b"%PDF")


def test_auth_registration_contract():
    client = app.test_client()
    response = client.post(
        "/api/v1/auth/register",
        json={"name": "Test User", "email": "test-user@example.com", "password": "Password123"},
    )
    assert response.status_code in {201, 400}
