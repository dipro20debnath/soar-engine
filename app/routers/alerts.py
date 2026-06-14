"""SOAR Engine - Alerts Query & Enrichment Router

Provides endpoints for querying, filtering, and viewing processed alerts.
Also provides manual enrichment triggers and enrichment cache management.
"""

import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Query

from app.models.alert import (
    NormalizedAlert,
    AlertSummary,
    AlertStats,
    AlertSeverity,
    AlertType,
    AlertStatus,
)
from app.models.enrichment import EnrichmentResult
from app.services.enrichment import (
    EnrichmentService,
    clear_enrichment_cache,
    get_cache_stats,
)
from app.services.risk_scorer import (
    calculate_risk_score,
    get_risk_level,
    get_risk_summary,
)
from app.db.store import alert_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["Alerts"])

# Shared enrichment service instance
_enrichment_service = EnrichmentService()


@router.get(
    "/alerts",
    response_model=list[AlertSummary],
    summary="List All Alerts",
    description="Retrieve alert summaries with optional filtering by severity, type, and status.",
)
async def list_alerts(
    severity: Optional[AlertSeverity] = Query(default=None, description="Filter by severity level"),
    alert_type: Optional[AlertType] = Query(default=None, description="Filter by alert type"),
    status: Optional[AlertStatus] = Query(default=None, description="Filter by processing status"),
    limit: int = Query(default=50, ge=1, le=500, description="Maximum alerts to return"),
    offset: int = Query(default=0, ge=0, description="Number of alerts to skip"),
) -> list[AlertSummary]:
    """List alerts with optional filters."""
    alerts = alert_store.get_all_alerts(
        severity=severity,
        alert_type=alert_type,
        status=status,
        limit=limit,
        offset=offset,
    )

    return [
        AlertSummary(
            alert_id=a.alert_id,
            timestamp=a.timestamp,
            alert_type=a.alert_type,
            severity=a.severity,
            status=a.status,
            source_ip=a.source_ip,
            description=a.description,
            risk_score=a.risk_score,
        )
        for a in alerts
    ]


@router.get(
    "/alerts/{alert_id}",
    response_model=NormalizedAlert,
    summary="Get Alert Details",
    description="Retrieve full details of a specific alert including enrichment data and response actions.",
)
async def get_alert(alert_id: str) -> NormalizedAlert:
    """Get full details of a specific alert by ID."""
    alert = alert_store.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert not found: {alert_id}")
    return alert


@router.get(
    "/stats",
    response_model=AlertStats,
    summary="Get Alert Statistics",
    description="Get aggregated statistics about all processed alerts.",
)
async def get_stats() -> AlertStats:
    """Get aggregate statistics for all alerts."""
    return alert_store.get_stats()


@router.delete(
    "/alerts/{alert_id}",
    summary="Delete Alert",
    description="Remove an alert from the system.",
)
async def delete_alert(alert_id: str) -> dict:
    """Delete a specific alert."""
    if alert_store.delete_alert(alert_id):
        return {"success": True, "message": f"Alert {alert_id} deleted"}
    raise HTTPException(status_code=404, detail=f"Alert not found: {alert_id}")


# ── Enrichment Endpoints ─────────────────────────────

@router.post(
    "/enrich/{alert_id}",
    summary="Manually Enrich Alert",
    description="Trigger threat intelligence enrichment for an existing alert. Re-queries AbuseIPDB and VirusTotal for all IoCs.",
    tags=["Enrichment"],
)
async def enrich_alert(alert_id: str) -> dict:
    """Manually trigger enrichment for an alert that was stored without enrichment.

    This is useful for:
    - Re-enriching alerts after adding new API keys
    - Enriching alerts that were received when enrichment was disabled
    - Getting updated threat intel for old alerts

    Args:
        alert_id: The alert ID to enrich.

    Returns:
        Dictionary with enrichment results, risk score, and risk summary.
    """
    alert = alert_store.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert not found: {alert_id}")

    if len(alert.iocs) == 0:
        return {
            "success": True,
            "alert_id": alert_id,
            "message": "No IoCs found in this alert — nothing to enrich",
            "risk_score": None,
        }

    # Run enrichment
    enrichment = _enrichment_service.enrich(alert)

    # Calculate risk score
    risk_score = calculate_risk_score(alert, enrichment)
    risk_level = get_risk_level(risk_score)

    # Update the alert in the store
    alert.risk_score = risk_score
    alert.enrichment_data = {
        "threat_level": enrichment.overall_threat_level,
        "confidence": enrichment.confidence,
        "ip_results_count": len(enrichment.ip_results),
        "hash_results_count": len(enrichment.hash_results),
        "notes": enrichment.notes,
        "enriched_at": enrichment.enriched_at.isoformat(),
    }
    alert.status = AlertStatus.ENRICHED
    if f"risk:{risk_level}" not in alert.tags:
        alert.tags.append(f"risk:{risk_level}")
    alert_store.update_alert(alert)

    logger.info(
        f"Manual enrichment for {alert_id}: "
        f"risk_score={risk_score}, level={risk_level}"
    )

    return {
        "success": True,
        "alert_id": alert_id,
        "risk_score": risk_score,
        "risk_summary": get_risk_summary(risk_score),
        "threat_level": enrichment.overall_threat_level,
        "confidence": enrichment.confidence,
        "ip_lookups": len(enrichment.ip_results),
        "hash_lookups": len(enrichment.hash_results),
        "notes": enrichment.notes,
    }


@router.get(
    "/enrichment/cache",
    summary="Enrichment Cache Stats",
    description="View the current enrichment cache statistics.",
    tags=["Enrichment"],
)
async def enrichment_cache_stats() -> dict:
    """Get statistics about the enrichment cache."""
    return {
        "success": True,
        **get_cache_stats(),
    }


@router.delete(
    "/enrichment/cache",
    summary="Clear Enrichment Cache",
    description="Clear all cached enrichment results. New lookups will query the APIs again.",
    tags=["Enrichment"],
)
async def clear_cache() -> dict:
    """Clear the enrichment cache to force fresh API lookups."""
    clear_enrichment_cache()
    return {
        "success": True,
        "message": "Enrichment cache cleared successfully",
    }

