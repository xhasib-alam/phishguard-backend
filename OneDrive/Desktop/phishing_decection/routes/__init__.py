"""Route registration for PhishGuard."""

from __future__ import annotations

from routes.admin import admin_bp
from routes.auth_routes import auth_bp
from routes.history import history_bp
from routes.reports import reports_bp
from routes.scan import scan_bp


def register_blueprints(app) -> None:
    app.register_blueprint(auth_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(admin_bp)
