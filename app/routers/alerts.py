"""SOAR Engine - Alerts Query Router

Provides endpoints for querying, filtering, and viewing processed alerts.
Used by the dashboard and SOC analysts to monitor alert status.
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
from app.db.store import alert_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["Alerts"])


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
