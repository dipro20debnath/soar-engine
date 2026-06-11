"""SOAR Engine - Alert Data Store

In-memory alert storage for Week 1-3.
Will be migrated to SQLite in Week 4 for persistence.

Provides thread-safe CRUD operations for alert management.
"""

import logging
from datetime import datetime
from typing import Optional

from app.models.alert import (
    NormalizedAlert,
    AlertStatus,
    AlertSeverity,
    AlertType,
    AlertStats,
    AlertSummary,
)

logger = logging.getLogger(__name__)


class AlertStore:
    """In-memory store for normalized alerts.
    
    Uses a dictionary for O(1) lookups by alert_id and
    maintains insertion order for chronological listing.
    """

    def __init__(self):
        """Initialize empty alert store."""
        self._alerts: dict[str, NormalizedAlert] = {}
        logger.info("AlertStore initialized (in-memory mode)")

    def add_alert(self, alert: NormalizedAlert) -> NormalizedAlert:
        """Add a new alert to the store.
        
        Args:
            alert: The normalized alert to store.
            
        Returns:
            The stored alert with its assigned ID.
        """
        self._alerts[alert.alert_id] = alert
        logger.info(f"Alert stored: {alert.alert_id} | Type: {alert.alert_type} | Severity: {alert.severity}")
        return alert

    def get_alert(self, alert_id: str) -> Optional[NormalizedAlert]:
        """Retrieve a single alert by ID.
        
        Args:
            alert_id: The unique identifier of the alert.
            
        Returns:
            The alert if found, None otherwise.
        """
        return self._alerts.get(alert_id)

    def get_all_alerts(
        self,
        severity: Optional[AlertSeverity] = None,
        alert_type: Optional[AlertType] = None,
        status: Optional[AlertStatus] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[NormalizedAlert]:
        """Get alerts with optional filtering.
        
        Args:
            severity: Filter by severity level.
            alert_type: Filter by alert type.
            status: Filter by processing status.
            limit: Maximum number of alerts to return.
            offset: Number of alerts to skip (for pagination).
            
        Returns:
            List of matching alerts, sorted by timestamp (newest first).
        """
        alerts = list(self._alerts.values())

        # Apply filters
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        if alert_type:
            alerts = [a for a in alerts if a.alert_type == alert_type]
        if status:
            alerts = [a for a in alerts if a.status == status]

        # Sort by timestamp (newest first)
        alerts.sort(key=lambda a: a.timestamp, reverse=True)

        # Apply pagination
        return alerts[offset: offset + limit]

    def update_alert(self, alert_id: str, **updates) -> Optional[NormalizedAlert]:
        """Update specific fields of an existing alert.
        
        Args:
            alert_id: The ID of the alert to update.
            **updates: Keyword arguments of fields to update.
            
        Returns:
            The updated alert, or None if not found.
        """
        alert = self._alerts.get(alert_id)
        if not alert:
            logger.warning(f"Alert not found for update: {alert_id}")
            return None

        # Update the alert fields
        alert_dict = alert.model_dump()
        alert_dict.update(updates)
        updated_alert = NormalizedAlert(**alert_dict)
        self._alerts[alert_id] = updated_alert

        logger.info(f"Alert updated: {alert_id} | Fields: {list(updates.keys())}")
        return updated_alert

    def delete_alert(self, alert_id: str) -> bool:
        """Delete an alert from the store.
        
        Args:
            alert_id: The ID of the alert to delete.
            
        Returns:
            True if deleted, False if not found.
        """
        if alert_id in self._alerts:
            del self._alerts[alert_id]
            logger.info(f"Alert deleted: {alert_id}")
            return True
        return False

    def get_stats(self) -> AlertStats:
        """Calculate aggregate statistics across all stored alerts.
        
        Returns:
            AlertStats with counts by severity, type, status, and averages.
        """
        alerts = list(self._alerts.values())

        if not alerts:
            return AlertStats()

        # Count by severity
        by_severity = {}
        for sev in AlertSeverity:
            count = sum(1 for a in alerts if a.severity == sev)
            if count > 0:
                by_severity[sev.value] = count

        # Count by type
        by_type = {}
        for at in AlertType:
            count = sum(1 for a in alerts if a.alert_type == at)
            if count > 0:
                by_type[at.value] = count

        # Count by status
        by_status = {}
        for st in AlertStatus:
            count = sum(1 for a in alerts if a.status == st)
            if count > 0:
                by_status[st.value] = count

        # Average risk score
        scored = [a.risk_score for a in alerts if a.risk_score is not None]
        avg_risk = sum(scored) / len(scored) if scored else None

        # Last alert time
        last_time = max(a.timestamp for a in alerts) if alerts else None

        return AlertStats(
            total_alerts=len(alerts),
            by_severity=by_severity,
            by_type=by_type,
            by_status=by_status,
            avg_risk_score=round(avg_risk, 2) if avg_risk else None,
            last_alert_time=last_time,
        )

    def get_summaries(self, limit: int = 50) -> list[AlertSummary]:
        """Get lightweight summaries for dashboard display.
        
        Args:
            limit: Maximum number of summaries to return.
            
        Returns:
            List of AlertSummary objects sorted by timestamp.
        """
        alerts = sorted(
            self._alerts.values(),
            key=lambda a: a.timestamp,
            reverse=True,
        )[:limit]

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

    @property
    def count(self) -> int:
        """Total number of alerts in the store."""
        return len(self._alerts)

    def clear(self) -> None:
        """Remove all alerts from the store."""
        self._alerts.clear()
        logger.info("AlertStore cleared")


# ── Global store instance ────────────────────────────────
# Single instance shared across the application
alert_store = AlertStore()
