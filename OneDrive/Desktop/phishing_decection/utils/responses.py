"""Consistent JSON response helpers."""

from __future__ import annotations

from http import HTTPStatus
from typing import Any

from flask import jsonify, request


def api_response(
    success: bool,
    data: Any | None = None,
    message: str | None = None,
    error: str | None = None,
    status_code: int = HTTPStatus.OK,
):
    payload = {
        "success": success,
        "message": message,
        "data": data,
        "error": error,
        "request_id": getattr(request, "request_id", None),
    }
    return jsonify(payload), status_code
