"""SOAR Engine - SQLite Store Tests (Day 19)

Tests the SQLiteAlertStore with the same operations as the in-memory store,
plus SQLite-specific features like persistence and SQL-based queries.

Uses ":memory:" SQLite databases so no files are created.
"""

import os
import tempfile
import unittest
from datetime import datetime, timezone

from app.models.alert import (
    NormalizedAlert,
    AlertType,
    AlertSeverity,
    AlertStatus,
    IoC,
)
from app.db.sqlite_store import SQLiteAlertStore


def _make_alert(
    alert_type: AlertType = AlertType.BRUTE_FORCE,
    severity: AlertSeverity = AlertSeverity.HIGH,
    risk_score: float = 65.0,
    source_ip: str = "103.24.55.12",
    target_host: str = "web-server-01",
    status: AlertStatus = AlertStatus.ENRICHED,
    description: str = "Test alert",
    tags: list = None,
    iocs: list = None,
) -> NormalizedAlert:
    """Create a test NormalizedAlert."""
    return NormalizedAlert(
        timestamp=datetime(2026, 6, 22, 10, 0, 0, tzinfo=timezone.utc),
        alert_type=alert_type,
        severity=severity,
        status=status,
        source_ip=source_ip,
        target_host=target_host,
        risk_score=risk_score,
        description=description,
        tags=tags or [],
        iocs=iocs or [],
    )


# ═════════════════════════════════════════════════════
# Base Test Class
# ═════════════════════════════════════════════════════

class SQLiteTestBase(unittest.TestCase):
    """Base class for SQLite tests using a temporary file db."""

    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.db_fd)  # Close the fd so sqlite can open it
        self.store = SQLiteAlertStore(db_path=self.db_path)

    def tearDown(self):
        try:
            os.remove(self.db_path)
            # Remove WAL files if they exist
            if os.path.exists(self.db_path + "-wal"):
                os.remove(self.db_path + "-wal")
            if os.path.exists(self.db_path + "-shm"):
                os.remove(self.db_path + "-shm")
        except OSError:
            pass

# ═════════════════════════════════════════════════════
# SQLite CRUD Tests
# ═════════════════════════════════════════════════════

class TestSQLiteCRUD(SQLiteTestBase):
    """Test basic CRUD operations on SQLiteAlertStore."""

    def test_add_and_get_alert(self):
        alert = _make_alert()
        self.store.add_alert(alert)
        retrieved = self.store.get_alert(alert.alert_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.alert_id, alert.alert_id)
        self.assertEqual(retrieved.alert_type, AlertType.BRUTE_FORCE)
        self.assertEqual(retrieved.severity, AlertSeverity.HIGH)

    def test_get_nonexistent_alert(self):
        result = self.store.get_alert("nonexistent-id")
        self.assertIsNone(result)

    def test_count(self):
        self.assertEqual(self.store.count, 0)
        self.store.add_alert(_make_alert())
        self.assertEqual(self.store.count, 1)
        self.store.add_alert(_make_alert())
        self.assertEqual(self.store.count, 2)

    def test_delete_alert(self):
        alert = _make_alert()
        self.store.add_alert(alert)
        self.assertTrue(self.store.delete_alert(alert.alert_id))
        self.assertIsNone(self.store.get_alert(alert.alert_id))
        self.assertEqual(self.store.count, 0)

    def test_delete_nonexistent(self):
        self.assertFalse(self.store.delete_alert("nonexistent"))

    def test_clear(self):
        for _ in range(5):
            self.store.add_alert(_make_alert())
        self.assertEqual(self.store.count, 5)
        self.store.clear()
        self.assertEqual(self.store.count, 0)


# ═════════════════════════════════════════════════════
# SQLite Field Serialization Tests
# ═════════════════════════════════════════════════════

class TestSQLiteSerialization(SQLiteTestBase):
    """Test that complex fields (IoCs, tags, etc.) survive round-trip serialization."""

    def test_iocs_roundtrip(self):
        alert = _make_alert(iocs=[
            IoC(ioc_type="ip", value="1.2.3.4", context="source"),
            IoC(ioc_type="hash", value="abc123def456", context="file"),
        ])
        self.store.add_alert(alert)
        retrieved = self.store.get_alert(alert.alert_id)
        self.assertEqual(len(retrieved.iocs), 2)
        self.assertEqual(retrieved.iocs[0].ioc_type, "ip")
        self.assertEqual(retrieved.iocs[0].value, "1.2.3.4")
        self.assertEqual(retrieved.iocs[1].ioc_type, "hash")

    def test_tags_roundtrip(self):
        alert = _make_alert(tags=["risk:high", "tor_exit", "repeat_offender"])
        self.store.add_alert(alert)
        retrieved = self.store.get_alert(alert.alert_id)
        self.assertEqual(retrieved.tags, ["risk:high", "tor_exit", "repeat_offender"])

    def test_enrichment_data_roundtrip(self):
        alert = _make_alert()
        alert.enrichment_data = {
            "threat_level": "high",
            "confidence": 0.95,
            "notes": ["Known malicious IP", "Tor exit node"],
        }
        self.store.add_alert(alert)
        retrieved = self.store.get_alert(alert.alert_id)
        self.assertEqual(retrieved.enrichment_data["threat_level"], "high")
        self.assertEqual(retrieved.enrichment_data["confidence"], 0.95)
        self.assertEqual(len(retrieved.enrichment_data["notes"]), 2)

    def test_response_actions_roundtrip(self):
        alert = _make_alert()
        alert.response_actions = ["block_ip:1.2.3.4", "notify_soc:critical", "isolate_host:web-01"]
        alert.playbook_name = "brute_force_response"
        self.store.add_alert(alert)
        retrieved = self.store.get_alert(alert.alert_id)
        self.assertEqual(len(retrieved.response_actions), 3)
        self.assertEqual(retrieved.playbook_name, "brute_force_response")

    def test_timestamp_roundtrip(self):
        alert = _make_alert()
        self.store.add_alert(alert)
        retrieved = self.store.get_alert(alert.alert_id)
        self.assertEqual(retrieved.timestamp.year, 2026)
        self.assertEqual(retrieved.timestamp.month, 6)

    def test_none_fields_roundtrip(self):
        alert = _make_alert(risk_score=None, source_ip=None, target_host=None)
        alert.risk_score = None
        self.store.add_alert(alert)
        retrieved = self.store.get_alert(alert.alert_id)
        self.assertIsNone(retrieved.risk_score)


# ═════════════════════════════════════════════════════
# SQLite Filtering & Query Tests
# ═════════════════════════════════════════════════════

class TestSQLiteFiltering(SQLiteTestBase):
    """Test SQL-based filtering and queries."""

    def setUp(self):
        super().setUp()
        # Seed with diverse alerts
        self.store.add_alert(_make_alert(AlertType.BRUTE_FORCE, AlertSeverity.HIGH, 80.0))
        self.store.add_alert(_make_alert(AlertType.MALWARE_DETECTED, AlertSeverity.CRITICAL, 95.0))
        self.store.add_alert(_make_alert(AlertType.SUSPICIOUS_LOGIN, AlertSeverity.MEDIUM, 45.0))
        self.store.add_alert(_make_alert(AlertType.PORT_SCAN, AlertSeverity.LOW, 20.0))
        self.store.add_alert(_make_alert(AlertType.BRUTE_FORCE, AlertSeverity.HIGH, 70.0))

    def test_filter_by_severity(self):
        results = self.store.get_all_alerts(severity=AlertSeverity.HIGH)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(a.severity == AlertSeverity.HIGH for a in results))

    def test_filter_by_type(self):
        results = self.store.get_all_alerts(alert_type=AlertType.BRUTE_FORCE)
        self.assertEqual(len(results), 2)

    def test_filter_by_status(self):
        results = self.store.get_all_alerts(status=AlertStatus.ENRICHED)
        self.assertEqual(len(results), 5)

    def test_pagination_limit(self):
        results = self.store.get_all_alerts(limit=2)
        self.assertEqual(len(results), 2)

    def test_pagination_offset(self):
        results = self.store.get_all_alerts(limit=2, offset=3)
        self.assertEqual(len(results), 2)

    def test_combined_filters(self):
        results = self.store.get_all_alerts(
            severity=AlertSeverity.HIGH,
            alert_type=AlertType.BRUTE_FORCE,
        )
        self.assertEqual(len(results), 2)

    def test_risk_level_filter(self):
        results = self.store.get_alerts_by_risk_level(min_score=70, max_score=100)
        self.assertEqual(len(results), 3)
        self.assertTrue(all(a.risk_score >= 70 for a in results))

    def test_risk_level_filter_sorted_descending(self):
        results = self.store.get_alerts_by_risk_level(min_score=0, max_score=100)
        scores = [a.risk_score for a in results]
        self.assertEqual(scores, sorted(scores, reverse=True))


# ═════════════════════════════════════════════════════
# SQLite Stats Tests
# ═════════════════════════════════════════════════════

class TestSQLiteStats(SQLiteTestBase):
    """Test aggregate statistics from SQLite."""

    def test_empty_stats(self):
        stats = self.store.get_stats()
        self.assertEqual(stats.total_alerts, 0)
        self.assertIsNone(stats.avg_risk_score)

    def test_stats_with_alerts(self):
        self.store.add_alert(_make_alert(AlertType.BRUTE_FORCE, AlertSeverity.HIGH, 80.0))
        self.store.add_alert(_make_alert(AlertType.MALWARE_DETECTED, AlertSeverity.CRITICAL, 90.0))
        self.store.add_alert(_make_alert(AlertType.PORT_SCAN, AlertSeverity.LOW, 30.0))

        stats = self.store.get_stats()
        self.assertEqual(stats.total_alerts, 3)
        self.assertIn("high", stats.by_severity)
        self.assertIn("critical", stats.by_severity)
        self.assertIn("brute_force", stats.by_type)
        self.assertAlmostEqual(stats.avg_risk_score, 66.67, places=1)

    def test_stats_by_status(self):
        self.store.add_alert(_make_alert(status=AlertStatus.ENRICHED))
        self.store.add_alert(_make_alert(status=AlertStatus.RESPONDED))

        stats = self.store.get_stats()
        self.assertIn("enriched", stats.by_status)
        self.assertIn("responded", stats.by_status)

    def test_summaries(self):
        self.store.add_alert(_make_alert())
        self.store.add_alert(_make_alert())
        summaries = self.store.get_summaries(limit=10)
        self.assertEqual(len(summaries), 2)


# ═════════════════════════════════════════════════════
# SQLite Update Tests
# ═════════════════════════════════════════════════════

class TestSQLiteUpdate(SQLiteTestBase):
    """Test alert update operations."""

    def test_update_with_full_alert(self):
        alert = _make_alert()
        self.store.add_alert(alert)

        alert.status = AlertStatus.RESPONDED
        alert.playbook_name = "brute_force_response"
        alert.response_actions = ["block_ip:1.2.3.4"]
        self.store.update_alert(alert)

        retrieved = self.store.get_alert(alert.alert_id)
        self.assertEqual(retrieved.status, AlertStatus.RESPONDED)
        self.assertEqual(retrieved.playbook_name, "brute_force_response")

    def test_update_nonexistent_returns_none(self):
        result = self.store.update_alert("nonexistent-id", status="responded")
        self.assertIsNone(result)

    def test_upsert_behavior(self):
        """Adding an alert with the same ID should replace it."""
        alert = _make_alert()
        self.store.add_alert(alert)

        alert.risk_score = 99.0
        alert.tags = ["updated"]
        self.store.add_alert(alert)

        self.assertEqual(self.store.count, 1)
        retrieved = self.store.get_alert(alert.alert_id)
        self.assertEqual(retrieved.risk_score, 99.0)
        self.assertIn("updated", retrieved.tags)


# ═════════════════════════════════════════════════════
# Store Interface Compatibility Tests
# ═════════════════════════════════════════════════════

class TestStoreInterfaceCompatibility(unittest.TestCase):
    """Verify that SQLiteAlertStore has the same interface as AlertStore."""

    def test_both_stores_have_same_methods(self):
        from app.db.memory_store import AlertStore

        memory_methods = {m for m in dir(AlertStore) if not m.startswith('_')}
        sqlite_methods = {m for m in dir(SQLiteAlertStore) if not m.startswith('_')}

        # SQLiteAlertStore should have all methods that AlertStore has
        missing = memory_methods - sqlite_methods
        self.assertEqual(
            missing, set(),
            f"SQLiteAlertStore is missing methods: {missing}"
        )


if __name__ == "__main__":
    unittest.main()
