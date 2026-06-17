"""PhishGuard application factory and production entrypoint."""

from __future__ import annotations

import logging
import os
import time
import uuid
from http import HTTPStatus

from dotenv import load_dotenv
from flask import Flask, Response, jsonify, render_template, request
from flask_cors import CORS
from werkzeug.exceptions import HTTPException

from config import settings
from database import init_app as init_database
from detector import PhishingDetector
from middleware import init_middleware
from routes import register_blueprints
from services.report_service import safe_filename
from services.report_service import ReportService
from services.scan_service import ScanService
from utils.responses import api_response
from utils.validation import is_valid_url, sanitize_url

load_dotenv()

APP_VERSION = "4.0.0"


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.update(
        JSON_SORT_KEYS=False,
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
        SECRET_KEY=settings.secret_key,
    )
    configure_logging(app)
    configure_cors(app)
    init_database(app)
    register_services(app)
    init_middleware(app)
    register_blueprints(app)
    register_web_routes(app)
    register_error_handlers(app)
    return app


def configure_logging(app: Flask) -> None:
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    app.logger.setLevel(getattr(logging, settings.log_level.upper(), logging.INFO))


def configure_cors(app: Flask) -> None:
    CORS(
        app,
        resources={r"/api/*": {"origins": settings.cors_origins.split(",")}},
        methods=["GET", "POST", "DELETE", "OPTIONS"],
    )


def register_services(app: Flask) -> None:
    detector = PhishingDetector(
        api_key=settings.safe_browsing_api_key,
        model_path=settings.model_path,
        enable_redirects=settings.enable_redirect_analysis,
        enable_ssl=settings.enable_ssl_verification,
    )
    app.extensions["detector"] = detector
    app.extensions["scan_service"] = ScanService(detector)
    app.extensions["report_service"] = ReportService()


def register_web_routes(app: Flask) -> None:
    @app.before_request
    def start_request_timer():
        request.start_time = time.perf_counter()
        request.request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))

    @app.after_request
    def add_security_headers(response):
        duration_ms = int((time.perf_counter() - getattr(request, "start_time", time.perf_counter())) * 1000)
        response.headers["X-Request-ID"] = getattr(request, "request_id", "")
        response.headers["X-Response-Time-ms"] = str(duration_ms)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https://www.google.com; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )
        return response

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/health")
    @app.get("/api/v1/health")
    def health_check():
        detector = app.extensions["detector"]
        return jsonify(
            {
                "status": "healthy",
                "service": "PhishGuard API",
                "version": APP_VERSION,
                "model_loaded": detector.model_loaded,
                "safe_browsing_enabled": bool(detector.api_key),
                "database": "online",
            }
        )

    @app.post("/check")
    def legacy_check():
        data = request.get_json(silent=True) or {}
        url = sanitize_url(data.get("url"))
        if not url or not is_valid_url(url):
            return jsonify({"error": "Invalid URL", "message": "Enter a valid URL or domain"}), HTTPStatus.BAD_REQUEST
        result = app.extensions["scan_service"].scan_url(url, persist=True)
        result["url"] = url
        return jsonify(result)

    @app.post("/api/v1/report")
    def legacy_report_json():
        data = request.get_json(silent=True) or {}
        url = sanitize_url(data.get("url"))
        if not url or not is_valid_url(url):
            return api_response(False, error="Valid URL is required", status_code=HTTPStatus.BAD_REQUEST)
        result = app.extensions["scan_service"].scan_url(url)
        result["url"] = url
        report = app.extensions["report_service"].create_report(result)
        return api_response(True, data=report, message="Report generated")

    @app.post("/api/v1/report.pdf")
    def legacy_report_pdf():
        data = request.get_json(silent=True) or {}
        url = sanitize_url(data.get("url"))
        if not url or not is_valid_url(url):
            return api_response(False, error="Valid URL is required", status_code=HTTPStatus.BAD_REQUEST)
        result = app.extensions["scan_service"].scan_url(url)
        result["url"] = url
        report = app.extensions["report_service"].create_report(result)
        pdf = app.extensions["report_service"].pdf(report)
        return Response(
            pdf,
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=phishguard-{safe_filename(result.get('domain', 'report'))}.pdf"},
        )


def register_error_handlers(app: Flask) -> None:
    @app.errorhandler(Exception)
    def handle_exception(error: Exception):
        if isinstance(error, HTTPException):
            return api_response(False, error=error.description, status_code=error.code or 500)
        app.logger.exception("Unhandled server error")
        return api_response(False, error="Unable to process the request right now.", status_code=HTTPStatus.INTERNAL_SERVER_ERROR)


app = create_app()


if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "0.0.0.0"), port=int(os.getenv("PORT", "5000")), debug=False)
