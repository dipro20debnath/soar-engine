"""
SOAR Incident Containment Engine
================================

Main FastAPI application entry point.
Initializes the SOAR engine with all routers, middleware, and startup events.

Run with:
    uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
"""

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse

from app.config import settings
from app.routers import webhooks, alerts, playbooks

# ── Logging Setup ──────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)-25s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# ── Application Lifespan ───────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events for the SOAR engine."""
    # ── Startup ──
    logger.info("=" * 60)
    logger.info(f"  {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info(f"  Simulation Mode: {'ON' if settings.SIMULATION_MODE else 'OFF'}")
    logger.info(f"  Enrichment: {'ENABLED' if settings.ENRICHMENT_ENABLED else 'DISABLED'}")
    logger.info(f"  AbuseIPDB Key: {'SET' if settings.ABUSEIPDB_API_KEY else 'NOT SET'}")
    logger.info(f"  VirusTotal Key: {'SET' if settings.VIRUSTOTAL_API_KEY else 'NOT SET'}")
    logger.info(f"  Debug Mode: {'ON' if settings.DEBUG else 'OFF'}")
    logger.info(f"  Server: http://{settings.HOST}:{settings.PORT}")
    logger.info(f"  Docs: http://{settings.HOST}:{settings.PORT}/docs")
    logger.info("=" * 60)

    yield

    # ── Shutdown ──
    logger.info("SOAR Engine shutting down...")


# ── FastAPI App ────────────────────────────────────────
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=settings.APP_DESCRIPTION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS Middleware ────────────────────────────────────
# Allow dashboard and external tools to access the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to specific domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Register Routers ──────────────────────────────────
app.include_router(webhooks.router)
app.include_router(alerts.router)
app.include_router(playbooks.router)


# ── Root Endpoint ─────────────────────────────────────
@app.get("/", tags=["Health"])
async def root():
    """Root endpoint — system info and available endpoints."""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "operational",
        "simulation_mode": settings.SIMULATION_MODE,
        "enrichment_enabled": settings.ENRICHMENT_ENABLED,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "endpoints": {
            "docs": "/docs",
            "receive_alert": "POST /api/alerts",
            "receive_bulk": "POST /api/alerts/bulk",
            "list_alerts": "GET /api/alerts",
            "alert_details": "GET /api/alerts/{alert_id}",
            "statistics": "GET /api/stats",
            "enrich_alert": "POST /api/enrich/{alert_id}",
            "cache_stats": "GET /api/enrichment/cache",
            "playbooks": "GET /api/playbooks",
            "playbook_history": "GET /api/playbooks/history",
            "pending_approvals": "GET /api/playbooks/pending",
            "approve_alert": "POST /api/playbooks/approve/{alert_id}",
            "reject_alert": "POST /api/playbooks/reject/{alert_id}",
            "blocklist": "GET /api/containment/blocklist",
            "isolated_instances": "GET /api/containment/isolated",
            "containment_summary": "GET /api/containment/summary",
        },
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """Detailed health check with enrichment and cache status."""
    from app.db.store import alert_store
    from app.services.enrichment import get_cache_stats

    cache = get_cache_stats()

    return {
        "status": "healthy",
        "uptime": datetime.now(timezone.utc).isoformat(),
        "alerts_in_store": alert_store.count,
        "simulation_mode": settings.SIMULATION_MODE,
        "enrichment": {
            "enabled": settings.ENRICHMENT_ENABLED,
            "abuseipdb_key_set": bool(settings.ABUSEIPDB_API_KEY),
            "virustotal_key_set": bool(settings.VIRUSTOTAL_API_KEY),
            "cache": cache,
        },
    }

