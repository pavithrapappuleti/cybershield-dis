"""Blueprint registration for CyberShield APIs."""

from .api import api_bp
from .auth import auth_bp
from .reports import reports_bp
from .simulation import simulation_bp

__all__ = ["api_bp", "auth_bp", "simulation_bp", "reports_bp"]
