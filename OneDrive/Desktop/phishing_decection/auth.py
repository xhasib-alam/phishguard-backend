"""Authentication helpers for password hashing and signed API tokens."""

from __future__ import annotations

from functools import wraps
from http import HTTPStatus

from flask import request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

from config import settings
from database import get_db, now_iso, row_to_dict, transaction
from utils.responses import api_response
from utils.validation import sanitize_text


def serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(settings.secret_key, salt="phishguard-auth")


def hash_password(password: str) -> str:
    return generate_password_hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    return check_password_hash(password_hash, password)


def create_token(user: dict) -> str:
    return serializer().dumps({"id": user["id"], "email": user["email"], "role": user["role"]})


def decode_token(token: str) -> dict | None:
    try:
        return serializer().loads(token, max_age=settings.token_ttl_seconds)
    except (BadSignature, SignatureExpired):
        return None


def register_user(name: str, email: str, password: str) -> tuple[dict | None, str | None]:
    name = sanitize_text(name, 120)
    email = sanitize_text(email, 255).lower()
    if not name or "@" not in email or len(password) < 8:
        return None, "Name, valid email, and password with at least 8 characters are required"

    try:
        with transaction() as db:
            cursor = db.execute(
                """
                INSERT INTO users (name, email, password_hash, role, email_verified, created_at)
                VALUES (?, ?, ?, 'user', 0, ?)
                """,
                (name, email, hash_password(password), now_iso()),
            )
            user = {"id": cursor.lastrowid, "name": name, "email": email, "role": "user"}
            db.execute(
                "INSERT INTO audit_logs (user_id, action, metadata_json, created_at) VALUES (?, ?, ?, ?)",
                (cursor.lastrowid, "user.registered", "{}", now_iso()),
            )
            return user, None
    except Exception:
        return None, "Email is already registered"


def authenticate_user(email: str, password: str) -> dict | None:
    row = get_db().execute("SELECT * FROM users WHERE email = ?", (sanitize_text(email, 255).lower(),)).fetchone()
    user = row_to_dict(row)
    if not user or not verify_password(user["password_hash"], password):
        return None
    return {"id": user["id"], "name": user["name"], "email": user["email"], "role": user["role"]}


def current_user(optional: bool = False):
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.removeprefix("Bearer ").strip() if auth_header.startswith("Bearer ") else ""
    payload = decode_token(token) if token else None
    if not payload:
        return None if optional else False
    return payload


def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            return api_response(False, error="Authentication required", status_code=HTTPStatus.UNAUTHORIZED)
        request.user = user
        return fn(*args, **kwargs)

    return wrapper


def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            return api_response(False, error="Authentication required", status_code=HTTPStatus.UNAUTHORIZED)
        if user.get("role") != "admin":
            return api_response(False, error="Administrator role required", status_code=HTTPStatus.FORBIDDEN)
        request.user = user
        return fn(*args, **kwargs)

    return wrapper
