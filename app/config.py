"""
SOAR Engine - Configuration Module

Loads environment variables and provides centralized configuration
for the entire application. Uses python-dotenv for .env file support.
"""

import os
from dotenv import load_dotenv

# Load .env file if it exists
load_dotenv()


class Settings:
    """Application-wide configuration settings."""

    # ── Server ──────────────────────────────────────────
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    DEBUG: bool = os.getenv("DEBUG", "true").lower() == "true"

    # ── Threat Intelligence API Keys (Week 2) ───────────
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")

    # ── AWS Configuration (Week 3) ──────────────────────
    AWS_REGION: str = os.getenv("AWS_REGION", "ap-south-1")
    AWS_ACCESS_KEY_ID: str = os.getenv("AWS_ACCESS_KEY_ID", "")
    AWS_SECRET_ACCESS_KEY: str = os.getenv("AWS_SECRET_ACCESS_KEY", "")

    # ── Simulation Mode ────────────────────────────────
    # When True, uses simulated API responses instead of real APIs
    SIMULATION_MODE: bool = os.getenv("SIMULATION_MODE", "true").lower() == "true"

    # ── Application Info ────────────────────────────────
    APP_NAME: str = "SOAR Incident Containment Engine"
    APP_VERSION: str = "1.0.0"
    APP_DESCRIPTION: str = (
        "Security Orchestration, Automation, and Response engine "
        "for automated threat detection, enrichment, and containment."
    )


# Global settings instance
settings = Settings()
