"""Application configuration for CyberShield Digital Immune System."""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
DATABASE_DIR = BASE_DIR / "database"
FRONTEND_DIR = PROJECT_ROOT / "frontend"


class Config:
    """Default local development configuration."""

    SECRET_KEY = os.environ.get("CYBERSHIELD_SECRET_KEY", "dev-only-cybershield-academic-key")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "CYBERSHIELD_DATABASE_URI",
        f"sqlite:///{(DATABASE_DIR / 'cybershield.db').as_posix()}",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JSON_SORT_KEYS = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    CORS_ORIGINS = os.environ.get("CYBERSHIELD_CORS_ORIGINS", "*")

    # Academic safe IP range prefixes (RFC 5737 TEST-NET-1, TEST-NET-2, TEST-NET-3)
    SIMULATED_IP_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")

    # Default safeguard: block duration in minutes for simulated sources
    DEFAULT_BLOCK_MINUTES = 15
    REQUIRE_HUMAN_APPROVAL_FOR_CRITICAL = False

    # Autonomous Self-Healing Watchdog settings
    AUTO_HEAL_ENABLED = True
    AUTO_HEAL_DELAY_SECONDS = 6

    # Local academic demo credentials for user portal login
    DEMO_AUTH_USERS = {
        "student": "DemoPass@123",
        "analyst": "CyberShield@2026",
    }

    # Admin-only CyberShield SOC Console credentials
    ADMIN_AUTH_USERS = {
        "admin": "AdminShield@2026",
    }
    ADMIN_AUTH_REQUIRED = True


class TestConfig(Config):
    """Configuration for automated test execution."""

    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    AUTO_HEAL_ENABLED = False
    ADMIN_AUTH_REQUIRED = False
