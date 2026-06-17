"""Request middleware for rate limiting and observability."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from http import HTTPStatus

from flask import request

from config import settings
from utils.responses import api_response

_request_windows: dict[str, deque[float]] = defaultdict(deque)


def init_middleware(app) -> None:
    @app.before_request
    def enforce_rate_limit():
        if request.endpoint == "static":
            return None

        client_id = request.headers.get("X-Forwarded-For", request.remote_addr or "anonymous").split(",")[0].strip()
        now = time.time()
        window = _request_windows[client_id]
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= settings.rate_limit_per_minute:
            return api_response(
                False,
                error="Rate limit exceeded. Please retry after one minute.",
                status_code=HTTPStatus.TOO_MANY_REQUESTS,
            )
        window.append(now)
        return None
