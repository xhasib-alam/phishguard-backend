"""Authentication API routes."""

from __future__ import annotations

from http import HTTPStatus

from flask import Blueprint, request

from auth import authenticate_user, create_token, register_user
from utils.responses import api_response

auth_bp = Blueprint("auth", __name__, url_prefix="/api/v1/auth")


@auth_bp.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    user, error = register_user(data.get("name", ""), data.get("email", ""), data.get("password", ""))
    if error:
        return api_response(False, error=error, status_code=HTTPStatus.BAD_REQUEST)
    return api_response(True, data={"user": user, "token": create_token(user)}, message="Registration successful", status_code=HTTPStatus.CREATED)


@auth_bp.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    user = authenticate_user(data.get("email", ""), data.get("password", ""))
    if not user:
        return api_response(False, error="Invalid email or password", status_code=HTTPStatus.UNAUTHORIZED)
    return api_response(True, data={"user": user, "token": create_token(user)}, message="Login successful")


@auth_bp.post("/logout")
def logout():
    return api_response(True, data={"revoked": True}, message="Client token cleared. Stateless token revocation can be added with a token blacklist.")


@auth_bp.post("/password-reset")
def password_reset():
    return api_response(True, data={"delivery": "email"}, message="Password reset workflow placeholder created")


@auth_bp.post("/verify-email")
def verify_email():
    return api_response(True, data={"verified": True}, message="Email verification workflow placeholder created")
