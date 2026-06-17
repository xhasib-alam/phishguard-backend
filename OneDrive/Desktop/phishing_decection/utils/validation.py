"""Input validation and sanitization helpers."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

MAX_URL_LENGTH = 2048


def sanitize_text(value: Any, max_length: int = 20000) -> str:
    if not isinstance(value, str):
        return ""
    cleaned = value.strip().replace("\x00", "")
    cleaned = re.sub(r"[\r\t]+", " ", cleaned)
    return cleaned[:max_length]


def sanitize_url(value: Any) -> str:
    return sanitize_text(value, MAX_URL_LENGTH).replace("\n", "")


def is_valid_url(value: str) -> bool:
    if len(value) < 3 or len(value) > MAX_URL_LENGTH:
        return False
    if re.search(r"\s|<|>|\"|'|`", value):
        return False
    if value.lower().startswith(("javascript:", "data:", "file:", "ftp:", "chrome:")):
        return False

    candidate = value if value.lower().startswith(("http://", "https://")) else f"http://{value}"
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    if parsed.port and not 1 <= parsed.port <= 65535:
        return False

    host = parsed.hostname
    return bool(
        re.fullmatch(r"([a-z0-9-]+\.)+[a-z]{2,}", host, re.IGNORECASE)
        or re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host)
    )
