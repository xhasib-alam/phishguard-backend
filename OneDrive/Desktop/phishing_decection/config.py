"""Application configuration for PhishGuard."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    env: str = os.getenv("FLASK_ENV", "production")
    secret_key: str = os.getenv("SECRET_KEY", "change-this-in-production")
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///instance/phishguard.db")
    cors_origins: str = os.getenv("CORS_ORIGINS", "*")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    model_path: str = os.getenv("MODEL_PATH", "models/model.pkl")
    safe_browsing_api_key: str = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    enable_redirect_analysis: bool = os.getenv("ENABLE_REDIRECT_ANALYSIS", "true").lower() == "true"
    enable_ssl_verification: bool = os.getenv("ENABLE_SSL_VERIFICATION", "true").lower() == "true"
    token_ttl_seconds: int = int(os.getenv("TOKEN_TTL_SECONDS", "86400"))
    rate_limit_per_minute: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))


settings = Settings()
