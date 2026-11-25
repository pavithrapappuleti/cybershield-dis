"""CyberShield Flask Application Factory and Server Entry Point."""

import logging
import os
from pathlib import Path
import sys
import time

from flask import Flask, g, jsonify, send_from_directory
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


def configure_logging(app):
    """Set up structured Python application logging."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    app.logger.setLevel(logging.INFO)


def create_app(config_class=Config, seed_baseline=True):
    """Create and configure the CyberShield Flask application."""
    frontend_folder = str(Path(__file__).resolve().parent.parent / "frontend")
    app = Flask(
        __name__,
        static_folder=frontend_folder,
        static_url_path="",
    )
    app.config.from_object(config_class)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    # Ensure database directory exists for file-backed SQLite
    db_dir = Path(__file__).resolve().parent / "database"
    db_dir.mkdir(parents=True, exist_ok=True)

    configure_logging(app)
    db.init_app(app)
    cors.init_app(app, resources={r"/api/*": {"origins": app.config.get("CORS_ORIGINS", "*")}})

    app.register_blueprint(api_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(simulation_bp)
    app.register_blueprint(reports_bp)

    @app.before_request
    def start_request_timer():
        g.request_started_at = time.perf_counter()

    @app.after_request
    def track_request_metrics(response):
        from flask import request

        started = getattr(g, "request_started_at", None)
        latency_ms = ((time.perf_counter() - started) * 1000.0) if started else 0.0
        if request.path.startswith("/api/"):
            record_http_activity(request.path, request.method, response.status_code, latency_ms)
        return response

    @app.errorhandler(404)
    def handle_not_found(err):
        from flask import request

        if request.path.startswith("/api/"):
            return jsonify({"error": "API endpoint not found."}), 404
        return send_from_directory(app.static_folder, "index.html")

    @app.errorhandler(500)
    def handle_server_error(err):
        app.logger.exception("Unhandled server error: %s", err)
        return jsonify({"error": "Internal server error occurred."}), 500

    @app.route("/", methods=["GET"])
    def serve_index():
        return send_from_directory(app.static_folder, "index.html")

    @app.route("/admin", methods=["GET"])
    def serve_admin():
        return send_from_directory(app.static_folder, "admin.html")

    with app.app_context():
        initialize_database(seed_baseline=seed_baseline)

    set_auto_heal_config(
        enabled=app.config.get("AUTO_HEAL_ENABLED", True),
        delay_seconds=app.config.get("AUTO_HEAL_DELAY_SECONDS", 6),
    )
    if not app.config.get("TESTING", False):
        start_autonomous_watchdog(app)

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="127.0.0.1", port=port, debug=debug)
