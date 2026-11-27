
"""CyberShield Flask Application Factory and Server Entry Point."""

import logging
import os
from pathlib import Path
import sys
import time

from flask import Flask, g, jsonify, request, send_from_directory
from flask.sessions import SecureCookieSessionInterface
from werkzeug.middleware.proxy_fix import ProxyFix

BACKEND_DIR = Path(__file__).resolve().parent

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from config import Config  # noqa: E402
from database.init_db import initialize_database  # noqa: E402
from extensions import cors, db  # noqa: E402
from routes import api_bp, auth_bp, reports_bp, simulation_bp  # noqa: E402
from services.monitoring_service import (  # noqa: E402
    record_http_activity,
    set_auto_heal_config,
    start_autonomous_watchdog,
)


# --------------------------------------------------
# LOGGING CONFIGURATION
# --------------------------------------------------

def configure_logging(app):
    """Set up structured Python application logging."""

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    app.logger.setLevel(logging.INFO)


# --------------------------------------------------
# CROSS-ORIGIN SESSION COOKIE CONFIGURATION
# --------------------------------------------------

class CrossOriginAwareSessionInterface(SecureCookieSessionInterface):
    """
    Configure secure session cookies.

    HTTPS:
        SameSite=None
        Secure=True

    Local HTTP:
        Uses Flask's default SameSite configuration.
    """

    def get_cookie_samesite(self, app):
        if request.is_secure:
            return "None"

        return super().get_cookie_samesite(app)

    def get_cookie_secure(self, app):
        if request.is_secure:
            return True

        return super().get_cookie_secure(app)


# --------------------------------------------------
# CORS CONFIGURATION
# --------------------------------------------------

def configure_cors(app):
    """
    Configure CORS for CyberShield.

    Allowed environments:
        Local Flask development
        Vercel frontend
        Render backend

    Credentials are enabled for session authentication.
    """

    configured_origins = app.config.get("CORS_ORIGINS", [])

    # Normalize configured origins.
    if isinstance(configured_origins, str):
        configured_origins = configured_origins.split(",")

    allowed_origins = {
        origin.strip().rstrip("/")
        for origin in configured_origins
        if isinstance(origin, str) and origin.strip()
    }

    # Optional Render environment override.
    environment_origins = os.environ.get(
        "CYBERSHIELD_CORS_ORIGINS",
        "",
    )

    if environment_origins:
        allowed_origins.update(
            origin.strip().rstrip("/")
            for origin in environment_origins.split(",")
            if origin.strip()
        )

    # Explicitly include the actual CyberShield deployment origins.
    required_origins = {
        "https://cybershield-ten-psi.vercel.app",
        "https://cybershield-dis-1.onrender.com",
        "http://127.0.0.1:5000",
        "http://localhost:5000",
    }

    allowed_origins.update(required_origins)

    # Convert to a stable list.
    allowed_origins = sorted(allowed_origins)

    app.logger.info(
        "CyberShield CORS allowed origins: %s",
        allowed_origins,
    )

    cors.init_app(
        app,
        resources={
            r"/api/*": {
                "origins": allowed_origins,
                "supports_credentials": True,
                "allow_headers": [
                    "Content-Type",
                    "Authorization",
                    "X-Simulated-Client-IP",
                ],
                "methods": [
                    "GET",
                    "POST",
                    "PATCH",
                    "PUT",
                    "DELETE",
                    "OPTIONS",
                ],
                "max_age": 600,
            }
        },
        vary_header=True,
        send_wildcard=False,
    )


# --------------------------------------------------
# APPLICATION FACTORY
# --------------------------------------------------

def create_app(config_class=Config, seed_baseline=True):
    """Create and configure the CyberShield Flask application."""

    frontend_folder = str(
        Path(__file__).resolve().parent.parent / "frontend"
    )

    app = Flask(
        __name__,
        static_folder=frontend_folder,
        static_url_path="",
    )

    # Load application configuration.
    app.config.from_object(config_class)

    # Configure cross-origin session cookies.
    app.session_interface = CrossOriginAwareSessionInterface()

    # Support reverse proxies such as Render.
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=1,
        x_proto=1,
        x_host=1,
    )

    # --------------------------------------------------
    # DATABASE DIRECTORY
    # --------------------------------------------------

    db_dir = Path(__file__).resolve().parent / "database"
    db_dir.mkdir(parents=True, exist_ok=True)

    # --------------------------------------------------
    # INITIALIZE EXTENSIONS
    # --------------------------------------------------

    configure_logging(app)

    db.init_app(app)

    configure_cors(app)

    # --------------------------------------------------
    # REGISTER BLUEPRINTS
    # --------------------------------------------------

    app.register_blueprint(api_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(simulation_bp)
    app.register_blueprint(reports_bp)

    # --------------------------------------------------
    # REQUEST MONITORING
    # --------------------------------------------------

    @app.before_request
    def start_request_timer():
        """Record request start time."""

        g.request_started_at = time.perf_counter()

    @app.after_request
    def track_request_metrics(response):
        """Record API request activity and response metrics."""

        started = getattr(
            g,
            "request_started_at",
            None,
        )

        latency_ms = (
            (time.perf_counter() - started) * 1000.0
            if started
            else 0.0
        )

        if request.path.startswith("/api/"):
            record_http_activity(
                request.path,
                request.method,
                response.status_code,
                latency_ms,
            )

        return response

    # --------------------------------------------------
    # ERROR HANDLERS
    # --------------------------------------------------

    @app.errorhandler(404)
    def handle_not_found(err):
        """Handle missing API endpoints and frontend routes."""

        if request.path.startswith("/api/"):
            return jsonify({
                "error": "API endpoint not found."
            }), 404

        return send_from_directory(
            app.static_folder,
            "index.html",
        )

    @app.errorhandler(500)
    def handle_server_error(err):
        """Handle internal server errors."""

        app.logger.exception(
            "Unhandled server error: %s",
            err,
        )

        return jsonify({
            "error": "Internal server error occurred."
        }), 500

    # --------------------------------------------------
    # FRONTEND ROUTES
    # --------------------------------------------------

    @app.route("/", methods=["GET"])
    def serve_index():
        """Serve the main user portal."""

        return send_from_directory(
            app.static_folder,
            "index.html",
        )

    @app.route("/admin", methods=["GET"])
    def serve_admin():
        """Serve the administrator dashboard."""

        return send_from_directory(
            app.static_folder,
            "admin.html",
        )

    # --------------------------------------------------
    # DATABASE INITIALIZATION
    # --------------------------------------------------

    with app.app_context():
        initialize_database(
            seed_baseline=seed_baseline
        )

    # --------------------------------------------------
    # AUTONOMOUS MONITORING AND SELF-HEALING
    # --------------------------------------------------

    set_auto_heal_config(
        enabled=app.config.get(
            "AUTO_HEAL_ENABLED",
            True,
        ),
        delay_seconds=app.config.get(
            "AUTO_HEAL_DELAY_SECONDS",
            6,
        ),
    )

    if not app.config.get("TESTING", False):
        start_autonomous_watchdog(app)

    app.logger.info(
        "CyberShield application initialized successfully."
    )

    return app


# --------------------------------------------------
# APPLICATION INSTANCE
# --------------------------------------------------

app = create_app()


# --------------------------------------------------
# DEVELOPMENT SERVER
# --------------------------------------------------

if __name__ == "__main__":

    port = int(
        os.environ.get("PORT", 5000)
    )

    debug = (
        os.environ.get(
            "FLASK_DEBUG",
            "false",
        ).lower() == "true"
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=debug,
    )
