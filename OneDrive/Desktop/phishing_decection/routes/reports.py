"""Report routes."""

from __future__ import annotations

from http import HTTPStatus

from flask import Blueprint, Response, current_app, request

from auth import current_user
from services.report_service import safe_filename
from utils.responses import api_response
from utils.validation import is_valid_url, sanitize_url

reports_bp = Blueprint("reports", __name__, url_prefix="/api/v1/reports")


def scan_service():
    return current_app.extensions["scan_service"]


def report_service():
    return current_app.extensions["report_service"]


@reports_bp.post("")
def create_report():
    data = request.get_json(silent=True) or {}
    url = sanitize_url(data.get("url"))
    if not url or not is_valid_url(url):
        return api_response(False, error="Valid URL is required", status_code=HTTPStatus.BAD_REQUEST)
    user = current_user(optional=True)
    result = scan_service().scan_url(url, user_id=user["id"] if user else None)
    result["url"] = url
    report = report_service().create_report(result, user_id=user["id"] if user else None)
    return api_response(True, data=report, message="Report generated")


@reports_bp.get("/<int:report_id>")
def get_report(report_id: int):
    user = current_user(optional=True)
    report = report_service().get_report(report_id, user_id=user["id"] if user else None)
    if not report:
        return api_response(False, error="Report not found", status_code=HTTPStatus.NOT_FOUND)
    return api_response(True, data=report, message="Report loaded")


@reports_bp.post("/pdf")
def create_pdf():
    data = request.get_json(silent=True) or {}
    url = sanitize_url(data.get("url"))
    if not url or not is_valid_url(url):
        return api_response(False, error="Valid URL is required", status_code=HTTPStatus.BAD_REQUEST)
    user = current_user(optional=True)
    result = scan_service().scan_url(url, user_id=user["id"] if user else None)
    result["url"] = url
    report = report_service().create_report(result, user_id=user["id"] if user else None)
    pdf = report_service().pdf(report)
    return Response(
        pdf,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=phishguard-{safe_filename(result.get('domain', 'report'))}.pdf"},
    )
