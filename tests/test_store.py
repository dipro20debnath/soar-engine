"""
Unit Tests - Alert Data Store

Tests the in-memory AlertStore including:
- CRUD operations (add, get, update, delete)
- Filtering and pagination
- Statistics aggregation
- Summary generation
"""

import pytest
from datetime import datetime

from app.db.store import AlertStore
from app.models.alert import (
    NormalizedAlert,
    AlertSeverity,
    AlertType,
    AlertStatus,
    IoC,
)


@pytest.fixture
def store():
    """Create a fresh AlertStore for each test."""
    return AlertStore()


@pytest.fixture
def sample_alert():
    """Create a sample normalized alert for testing."""
    return NormalizedAlert(
        timestamp=datetime(2026, 6, 11, 10, 0, 0),
        alert_type=AlertType.BRUTE_FORCE,
        severity=AlertSeverity.HIGH,
        status=AlertStatus.NORMALIZED,
        source_ip="103.24.55.12",
        target_host="web-server-01",
        description="Brute force attack detected",
        iocs=[
            IoC(ioc_type="ip", value="103.24.55.12", context="Source IP"),
        ],
    )


class TestAlertStoreBasicOperations:
    """Tests for basic CRUD operations."""

    def test_add_alert(self, store, sample_alert):
        """Should add an alert and return it with an ID."""
        result = store.add_alert(sample_alert)
        assert result.alert_id == sample_alert.alert_id
        assert store.count == 1

    def test_get_alert(self, store, sample_alert):
        """Should retrieve an alert by ID."""
        store.add_alert(sample_alert)
        result = store.get_alert(sample_alert.alert_id)
        assert result is not None
        assert result.alert_id == sample_alert.alert_id
        assert result.source_ip == "103.24.55.12"

    def test_get_nonexistent_alert(self, store):
        """Should return None for nonexistent alert ID."""
        result = store.get_alert("nonexistent-id")
        assert result is None

    def test_delete_alert(self, store, sample_alert):
        """Should delete an alert and return True."""
        store.add_alert(sample_alert)
        assert store.delete_alert(sample_alert.alert_id) is True
        assert store.count == 0
        assert store.get_alert(sample_alert.alert_id) is None

    def test_delete_nonexistent(self, store):
        """Should return False when deleting nonexistent alert."""
        assert store.delete_alert("nonexistent-id") is False

    def test_update_alert(self, store, sample_alert):
        """Should update specific fields of an alert."""
        store.add_alert(sample_alert)
        updated = store.update_alert(
            sample_alert.alert_id,
            status=AlertStatus.ENRICHED,
            risk_score=85.5,
        )
        assert updated is not None
        assert updated.status == AlertStatus.ENRICHED
        assert updated.risk_score == 85.5

    def test_clear_store(self, store, sample_alert):
        """Should remove all alerts."""
        store.add_alert(sample_alert)
        store.clear()
        assert store.count == 0


class TestAlertStoreFiltering:
    """Tests for filtering and pagination."""

    def _add_multiple_alerts(self, store):
        """Helper to add alerts of different types and severities."""
        alerts = [
            NormalizedAlert(
                timestamp=datetime(2026, 6, 11, 10, 0, 0),
                alert_type=AlertType.BRUTE_FORCE,
                severity=AlertSeverity.HIGH,
            ),
            NormalizedAlert(
                timestamp=datetime(2026, 6, 11, 11, 0, 0),
                alert_type=AlertType.MALWARE_DETECTED,
                severity=AlertSeverity.CRITICAL,
            ),
            NormalizedAlert(
                timestamp=datetime(2026, 6, 11, 12, 0, 0),
                alert_type=AlertType.BRUTE_FORCE,
                severity=AlertSeverity.MEDIUM,
            ),
        ]
        for alert in alerts:
            store.add_alert(alert)
        return alerts

    def test_filter_by_severity(self, store):
        """Should filter alerts by severity level."""
        self._add_multiple_alerts(store)
        high_alerts = store.get_all_alerts(severity=AlertSeverity.HIGH)
        assert len(high_alerts) == 1

    def test_filter_by_type(self, store):
        """Should filter alerts by alert type."""
        self._add_multiple_alerts(store)
        brute_force = store.get_all_alerts(alert_type=AlertType.BRUTE_FORCE)
        assert len(brute_force) == 2

    def test_pagination(self, store):
        """Should support limit and offset for pagination."""
        self._add_multiple_alerts(store)
        page1 = store.get_all_alerts(limit=2, offset=0)
        page2 = store.get_all_alerts(limit=2, offset=2)
        assert len(page1) == 2
        assert len(page2) == 1

    def test_sorted_by_timestamp(self, store):
        """Should return alerts sorted by timestamp (newest first)."""
        self._add_multiple_alerts(store)
        alerts = store.get_all_alerts()
        assert alerts[0].timestamp > alerts[-1].timestamp


class TestAlertStoreStatistics:
    """Tests for statistics aggregation."""

    def test_empty_stats(self, store):
        """Should return zero stats for empty store."""
        stats = store.get_stats()
        assert stats.total_alerts == 0
        assert stats.avg_risk_score is None

    def test_stats_with_alerts(self, store):
        """Should calculate correct statistics."""
        store.add_alert(NormalizedAlert(
            timestamp=datetime(2026, 6, 11, 10, 0, 0),
            alert_type=AlertType.BRUTE_FORCE,
            severity=AlertSeverity.HIGH,
            risk_score=80.0,
        ))
        store.add_alert(NormalizedAlert(
            timestamp=datetime(2026, 6, 11, 11, 0, 0),
            alert_type=AlertType.MALWARE_DETECTED,
            severity=AlertSeverity.CRITICAL,
            risk_score=95.0,
        ))
        stats = store.get_stats()
        assert stats.total_alerts == 2
        assert "high" in stats.by_severity
        assert "critical" in stats.by_severity
        assert stats.avg_risk_score == 87.5

    def test_summaries(self, store, sample_alert):
        """Should return lightweight alert summaries."""
        store.add_alert(sample_alert)
        summaries = store.get_summaries()
        assert len(summaries) == 1
        assert summaries[0].alert_id == sample_alert.alert_id
        assert summaries[0].severity == AlertSeverity.HIGH
