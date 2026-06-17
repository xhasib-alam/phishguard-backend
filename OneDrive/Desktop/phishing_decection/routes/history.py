"""Scan history and analytics routes."""

from __future__ import annotations

from flask import Blueprint, current_app, request

from auth import current_user
from utils.responses import api_response
from utils.validation import sanitize_text

history_bp = Blueprint("history", __name__, url_prefix="/api/v1/history")


def scan_service():
    return current_app.extensions["scan_service"]


@history_bp.get("")
def list_history():
    user = current_user(optional=True)
    query = sanitize_text(request.args.get("q", ""), 120)
    verdict = sanitize_text(request.args.get("verdict", ""), 30)
    data = scan_service().history(user_id=user["id"] if user else None, query=query, verdict=verdict)
    return api_response(True, data=data, message="History loaded")


@history_bp.get("/analytics")
def analytics():
    user = current_user(optional=True)
    return api_response(True, data=scan_service().analytics(user_id=user["id"] if user else None), message="Analytics loaded")
