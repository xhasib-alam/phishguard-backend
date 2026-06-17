"""Administrator API routes."""

from __future__ import annotations

from flask import Blueprint, current_app

from auth import require_admin
from database import get_db
from services.model_service import performance_summary
from utils.responses import api_response

admin_bp = Blueprint("admin", __name__, url_prefix="/api/v1/admin")


@admin_bp.get("/overview")
@require_admin
def overview():
    db = get_db()
    users = db.execute("SELECT COUNT(*) AS total FROM users").fetchone()["total"]
    scans = db.execute("SELECT COUNT(*) AS total FROM scans").fetchone()["total"]
    reports = db.execute("SELECT COUNT(*) AS total FROM reports").fetchone()["total"]
    analytics = current_app.extensions["scan_service"].analytics()
    return api_response(
        True,
        data={
            "total_users": users,
            "total_scans": scans,
            "total_reports": reports,
            "threat_statistics": analytics,
            "system_health": {"api": "online", "database": "online"},
            "model_performance": performance_summary(),
        },
        message="Admin overview loaded",
    )
