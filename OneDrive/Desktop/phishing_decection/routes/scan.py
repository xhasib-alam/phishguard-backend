"""Scan-related API routes."""

from __future__ import annotations

from http import HTTPStatus

from flask import Blueprint, current_app, request

from auth import current_user
from services.email_service import EmailAnalyzer
from utils.responses import api_response
from utils.validation import is_valid_url, sanitize_text, sanitize_url

scan_bp = Blueprint("scan", __name__, url_prefix="/api/v1")


def scan_service():
    return current_app.extensions["scan_service"]


@scan_bp.post("/scan")
def scan_url():
    data = request.get_json(silent=True) or {}
    url = sanitize_url(data.get("url"))
    if not url or not is_valid_url(url):
        return api_response(False, error="Enter a valid HTTP/HTTPS URL, domain, or IPv4 target", status_code=HTTPStatus.BAD_REQUEST)
    user = current_user(optional=True)
    result = scan_service().scan_url(url, user_id=user["id"] if user else None)
    result["url"] = url
    return api_response(True, data=mobile_scan_payload(result), message="URL analysis completed")


@scan_bp.post("/bulk-scan")
def bulk_scan():
    data = request.get_json(silent=True) or {}
    urls = data.get("urls", [])
    if isinstance(urls, str):
        urls = [line.strip() for line in urls.splitlines() if line.strip()]
    if not isinstance(urls, list) or not urls:
        return api_response(False, error="Provide urls as an array or newline-separated string", status_code=HTTPStatus.BAD_REQUEST)
    user = current_user(optional=True)
    results = []
    for raw_url in urls[:100]:
        url = sanitize_url(raw_url)
        if not is_valid_url(url):
            results.append({"url": raw_url, "success": False, "error": "Invalid URL"})
            continue
        result = scan_service().scan_url(url, user_id=user["id"] if user else None)
        result["url"] = url
        results.append({"url": url, "success": True, "result": mobile_scan_payload(result)})
    return api_response(True, data={"count": len(results), "results": results}, message="Bulk scan completed")


@scan_bp.post("/email/analyze")
def analyze_email():
    data = request.get_json(silent=True) or {}
    content = sanitize_text(data.get("content"))
    if not content:
        return api_response(False, error="Email content is required", status_code=HTTPStatus.BAD_REQUEST)
    return api_response(True, data=EmailAnalyzer().analyze(content), message="Email analysis completed")


@scan_bp.post("/qr/analyze")
def analyze_qr_placeholder():
    return api_response(
        True,
        data={"status": "planned", "supported_formats": ["png", "jpg", "jpeg"], "next_step": "Install pyzbar/opencv for QR extraction in production"},
        message="QR phishing API contract is ready",
    )


@scan_bp.get("/model/performance")
def model_performance():
    from services.model_service import performance_summary

    return api_response(True, data=performance_summary(), message="Model performance loaded")


def mobile_scan_payload(result: dict) -> dict:
    """Expose the requested flat Android-ready fields plus the detailed report."""
    return {
        "success": True,
        "status": result.get("verdict"),
        "verdict": result.get("verdict"),
        "confidence": result.get("confidence"),
        "risk_score": result.get("risk_score"),
        "risk_level": result.get("risk_level"),
        "domain": result.get("domain"),
        "reasons": result.get("analysis", []),
        "recommendations": result.get("recommended_actions", []),
        "scan_id": result.get("scan_id"),
        "source": result.get("source"),
        "timestamp": result.get("timestamp"),
        "details": result,
    }
