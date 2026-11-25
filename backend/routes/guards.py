"""Access-control decorator for Admin-only CyberShield SOC endpoints."""

from functools import wraps
from flask import current_app, jsonify, session


def admin_required(fn):
    """Restrict access to authenticated CyberShield SOC administrators."""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if current_app.config.get("ADMIN_AUTH_REQUIRED", True):
            if not session.get("admin_user"):
                return jsonify({"error": "Administrator authentication required."}), 401
        return fn(*args, **kwargs)

    return wrapper
