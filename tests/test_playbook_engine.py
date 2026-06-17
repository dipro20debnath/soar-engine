"""SOAR Engine - Playbook Engine & Playbook Unit Tests

Tests cover:
    1. BasePlaybook interface contract
    2. Individual playbook action logic at different risk levels
    3. PlaybookEngine alert-to-playbook mapping
    4. Default fallback for unmapped alert types
    5. Alert mutation (playbook_name, response_actions populated)
    6. Execution history tracking
"""

import unittest
from datetime import datetime, timezone
from typing import Optional

from app.models.alert import (
    NormalizedAlert,
    AlertType,
    AlertSeverity,
    AlertStatus,
    IoC,
)
from app.models.enrichment import EnrichmentResult
from app.playbooks.base import BasePlaybook
from app.playbooks.default import DefaultPlaybook
from app.playbooks.brute_force import BruteForcePlaybook
from app.playbooks.malware_detected import MalwareDetectedPlaybook
from app.playbooks.suspicious_login import SuspiciousLoginPlaybook
from app.services.playbook_engine import PlaybookEngine


# ── Helpers ───────────────────────────────────────────

def _make_alert(
    alert_type: AlertType = AlertType.UNKNOWN,
    severity: AlertSeverity = AlertSeverity.MEDIUM,
    risk_score: Optional[float] = None,
    source_ip: str = "103.24.55.12",
    target_host: str = "web-server-01",
    iocs: Optional[list[IoC]] = None,
) -> NormalizedAlert:
    """Create a test NormalizedAlert with sensible defaults."""
    return NormalizedAlert(
        timestamp=datetime(2026, 6, 18, 10, 0, 0, tzinfo=timezone.utc),
        alert_type=alert_type,
        severity=severity,
        status=AlertStatus.ENRICHED,
        source_ip=source_ip,
        target_host=target_host,
        risk_score=risk_score,
        description="Test alert",
        iocs=iocs or [],
    )


# ═════════════════════════════════════════════════════
# BasePlaybook Tests
# ═════════════════════════════════════════════════════

class TestBasePlaybook(unittest.TestCase):
    """Test that BasePlaybook enforces the abstract interface."""

    def test_cannot_instantiate_directly(self):
        """BasePlaybook is abstract — direct instantiation should fail."""
        with self.assertRaises(TypeError):
            BasePlaybook()

    def test_risk_score_helper_with_score(self):
        """_get_risk_score returns the alert's risk score when present."""
        playbook = DefaultPlaybook()  # concrete subclass
        alert = _make_alert(risk_score=72.5)
        self.assertEqual(playbook._get_risk_score(alert), 72.5)

    def test_risk_score_helper_without_score(self):
        """_get_risk_score returns 0.0 when risk_score is None."""
        playbook = DefaultPlaybook()
        alert = _make_alert(risk_score=None)
        self.assertEqual(playbook._get_risk_score(alert), 0.0)


# ═════════════════════════════════════════════════════
# DefaultPlaybook Tests
# ═════════════════════════════════════════════════════

class TestDefaultPlaybook(unittest.TestCase):
    """Test the fallback default playbook."""

    def setUp(self):
        self.playbook = DefaultPlaybook()

    def test_name_and_description(self):
        self.assertEqual(self.playbook.name, "default_triage")
        self.assertIn("default", self.playbook.description.lower())

    def test_low_risk_logs_only(self):
        alert = _make_alert(risk_score=20.0)
        actions = self.playbook.execute(alert)
        self.assertTrue(any("log_alert" in a for a in actions))
        self.assertNotIn("assign_triage_ticket", actions)

    def test_medium_risk_assigns_ticket(self):
        alert = _make_alert(risk_score=55.0)
        actions = self.playbook.execute(alert)
        self.assertIn("assign_triage_ticket", actions)
        self.assertNotIn("escalate_to_senior_analyst", actions)

    def test_high_risk_escalates(self):
        alert = _make_alert(risk_score=80.0)
        actions = self.playbook.execute(alert)
        self.assertIn("assign_triage_ticket", actions)
        self.assertIn("escalate_to_senior_analyst", actions)


# ═════════════════════════════════════════════════════
# BruteForcePlaybook Tests
# ═════════════════════════════════════════════════════

class TestBruteForcePlaybook(unittest.TestCase):
    """Test brute-force response playbook at each risk tier."""

    def setUp(self):
        self.playbook = BruteForcePlaybook()

    def test_name_and_description(self):
        self.assertEqual(self.playbook.name, "brute_force_response")
        self.assertIn("brute", self.playbook.description.lower())

    def test_low_risk_logs_only(self):
        alert = _make_alert(alert_type=AlertType.BRUTE_FORCE, risk_score=15.0)
        actions = self.playbook.execute(alert)
        self.assertEqual(actions, ["log_only"])

    def test_medium_risk_watchlists_ip(self):
        alert = _make_alert(
            alert_type=AlertType.BRUTE_FORCE,
            risk_score=50.0,
            source_ip="185.220.101.45",
        )
        actions = self.playbook.execute(alert)
        self.assertIn("add_to_watchlist:185.220.101.45", actions)
        self.assertIn("notify_soc:warning", actions)

    def test_high_risk_blocks_ip(self):
        alert = _make_alert(
            alert_type=AlertType.BRUTE_FORCE,
            risk_score=85.0,
            source_ip="103.24.55.12",
        )
        actions = self.playbook.execute(alert)
        self.assertIn("block_ip:103.24.55.12", actions)
        self.assertIn("notify_soc:critical", actions)

    def test_boundary_30_is_medium(self):
        """Risk score exactly 30 should trigger medium-tier actions."""
        alert = _make_alert(alert_type=AlertType.BRUTE_FORCE, risk_score=30.0)
        actions = self.playbook.execute(alert)
        self.assertTrue(any("watchlist" in a for a in actions))

    def test_boundary_75_is_still_medium(self):
        """Risk score exactly 75 is not > 75, so should be medium tier."""
        alert = _make_alert(alert_type=AlertType.BRUTE_FORCE, risk_score=75.0)
        actions = self.playbook.execute(alert)
        self.assertTrue(any("watchlist" in a for a in actions))


# ═════════════════════════════════════════════════════
# MalwareDetectedPlaybook Tests
# ═════════════════════════════════════════════════════

class TestMalwareDetectedPlaybook(unittest.TestCase):
    """Test malware detection response playbook at each risk tier."""

    def setUp(self):
        self.playbook = MalwareDetectedPlaybook()
        self.hash_ioc = IoC(
            ioc_type="hash_sha256",
            value="e99a18c428cb38d5f260853678922e03abc1234567890abcdef1234567890ab",
            context="test",
        )

    def test_name_and_description(self):
        self.assertEqual(self.playbook.name, "malware_response")
        self.assertIn("malware", self.playbook.description.lower())

    def test_low_risk_monitors(self):
        alert = _make_alert(
            alert_type=AlertType.MALWARE_DETECTED,
            risk_score=30.0,
            iocs=[self.hash_ioc],
        )
        actions = self.playbook.execute(alert)
        self.assertEqual(actions, ["log_and_monitor"])

    def test_medium_risk_quarantines_hash(self):
        alert = _make_alert(
            alert_type=AlertType.MALWARE_DETECTED,
            risk_score=65.0,
            iocs=[self.hash_ioc],
        )
        actions = self.playbook.execute(alert)
        self.assertTrue(any("quarantine_hash" in a for a in actions))
        self.assertIn("notify_soc:warning", actions)

    def test_high_risk_isolates_host(self):
        alert = _make_alert(
            alert_type=AlertType.MALWARE_DETECTED,
            risk_score=90.0,
            iocs=[self.hash_ioc],
        )
        actions = self.playbook.execute(alert)
        self.assertIn("isolate_host:web-server-01", actions)
        self.assertTrue(any("quarantine_hash" in a for a in actions))
        self.assertIn("notify_soc:critical", actions)

    def test_no_iocs_still_works(self):
        """Playbook should handle alerts with no file hashes gracefully."""
        alert = _make_alert(
            alert_type=AlertType.MALWARE_DETECTED, risk_score=90.0, iocs=[]
        )
        actions = self.playbook.execute(alert)
        self.assertIn("isolate_host:web-server-01", actions)


# ═════════════════════════════════════════════════════
# SuspiciousLoginPlaybook Tests
# ═════════════════════════════════════════════════════

class TestSuspiciousLoginPlaybook(unittest.TestCase):
    """Test suspicious login response playbook at each risk tier."""

    def setUp(self):
        self.playbook = SuspiciousLoginPlaybook()

    def test_name_and_description(self):
        self.assertEqual(self.playbook.name, "suspicious_login_response")
        self.assertIn("login", self.playbook.description.lower())

    def test_low_risk_logs_only(self):
        alert = _make_alert(
            alert_type=AlertType.SUSPICIOUS_LOGIN, risk_score=20.0
        )
        actions = self.playbook.execute(alert)
        self.assertEqual(actions, ["log_only"])

    def test_medium_risk_resets_password(self):
        alert = _make_alert(
            alert_type=AlertType.SUSPICIOUS_LOGIN, risk_score=55.0
        )
        actions = self.playbook.execute(alert)
        self.assertIn("force_password_reset", actions)
        self.assertIn("notify_user", actions)

    def test_high_risk_locks_account(self):
        alert = _make_alert(
            alert_type=AlertType.SUSPICIOUS_LOGIN,
            risk_score=85.0,
            source_ip="77.88.55.66",
        )
        actions = self.playbook.execute(alert)
        self.assertIn("lock_account", actions)
        self.assertIn("block_ip:77.88.55.66", actions)
        self.assertIn("notify_soc:critical", actions)


# ═════════════════════════════════════════════════════
# PlaybookEngine Tests
# ═════════════════════════════════════════════════════

class TestPlaybookEngine(unittest.TestCase):
    """Test the central playbook engine orchestration."""

    def setUp(self):
        self.engine = PlaybookEngine()

    def test_maps_brute_force_to_playbook(self):
        pb = self.engine.get_playbook(AlertType.BRUTE_FORCE)
        self.assertIsInstance(pb, BruteForcePlaybook)

    def test_maps_malware_to_playbook(self):
        pb = self.engine.get_playbook(AlertType.MALWARE_DETECTED)
        self.assertIsInstance(pb, MalwareDetectedPlaybook)

    def test_maps_suspicious_login_to_playbook(self):
        pb = self.engine.get_playbook(AlertType.SUSPICIOUS_LOGIN)
        self.assertIsInstance(pb, SuspiciousLoginPlaybook)

    def test_unknown_type_uses_default(self):
        pb = self.engine.get_playbook(AlertType.UNKNOWN)
        self.assertIsInstance(pb, DefaultPlaybook)

    def test_port_scan_uses_default(self):
        pb = self.engine.get_playbook(AlertType.PORT_SCAN)
        self.assertIsInstance(pb, DefaultPlaybook)

    def test_execute_populates_alert_fields(self):
        """After execution, alert.playbook_name and response_actions should be set."""
        alert = _make_alert(
            alert_type=AlertType.BRUTE_FORCE, risk_score=85.0
        )
        self.assertIsNone(alert.playbook_name)
        self.assertEqual(alert.response_actions, [])

        actions = self.engine.execute(alert)

        self.assertEqual(alert.playbook_name, "brute_force_response")
        self.assertEqual(alert.response_actions, actions)
        self.assertTrue(len(actions) > 0)

    def test_execute_with_no_risk_score(self):
        """Engine should handle alerts with risk_score=None (defaults to 0.0)."""
        alert = _make_alert(
            alert_type=AlertType.BRUTE_FORCE, risk_score=None
        )
        actions = self.engine.execute(alert)
        self.assertEqual(actions, ["log_only"])
        self.assertEqual(alert.playbook_name, "brute_force_response")

    def test_execute_records_history(self):
        """Each execution should add an entry to the history."""
        self.assertEqual(self.engine.history_count, 0)

        alert = _make_alert(alert_type=AlertType.BRUTE_FORCE, risk_score=50.0)
        self.engine.execute(alert)

        self.assertEqual(self.engine.history_count, 1)
        history = self.engine.get_history()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["playbook_name"], "brute_force_response")
        self.assertEqual(history[0]["alert_type"], "brute_force")

    def test_history_ordered_newest_first(self):
        """History should return most recent executions first."""
        for risk in [20.0, 50.0, 85.0]:
            alert = _make_alert(alert_type=AlertType.BRUTE_FORCE, risk_score=risk)
            self.engine.execute(alert)

        history = self.engine.get_history()
        self.assertEqual(len(history), 3)
        # Most recent execution (risk=85) should be first
        self.assertEqual(history[0]["risk_score"], 85.0)

    def test_clear_history(self):
        alert = _make_alert(alert_type=AlertType.BRUTE_FORCE, risk_score=50.0)
        self.engine.execute(alert)
        self.assertEqual(self.engine.history_count, 1)

        self.engine.clear_history()
        self.assertEqual(self.engine.history_count, 0)

    def test_get_registered_playbooks(self):
        """Should list all registered playbooks including the default."""
        registered = self.engine.get_registered_playbooks()
        self.assertIn("brute_force", registered)
        self.assertIn("malware_detected", registered)
        self.assertIn("suspicious_login", registered)
        self.assertIn("_default", registered)

    def test_execute_default_for_unknown_type(self):
        """Unknown alert type should trigger the default playbook."""
        alert = _make_alert(alert_type=AlertType.UNKNOWN, risk_score=55.0)
        actions = self.engine.execute(alert)
        self.assertEqual(alert.playbook_name, "default_triage")
        self.assertIn("assign_triage_ticket", actions)

    def test_execute_default_for_port_scan(self):
        """Port scan (no dedicated playbook) should use default."""
        alert = _make_alert(alert_type=AlertType.PORT_SCAN, risk_score=80.0)
        actions = self.engine.execute(alert)
        self.assertEqual(alert.playbook_name, "default_triage")
        self.assertIn("escalate_to_senior_analyst", actions)

    def test_full_pipeline_brute_force_high_risk(self):
        """Integration: High-risk brute force goes through full engine."""
        alert = _make_alert(
            alert_type=AlertType.BRUTE_FORCE,
            risk_score=92.0,
            source_ip="185.220.101.45",
        )
        actions = self.engine.execute(alert)
        self.assertIn("block_ip:185.220.101.45", actions)
        self.assertIn("notify_soc:critical", actions)
        self.assertEqual(alert.playbook_name, "brute_force_response")
        self.assertEqual(alert.response_actions, actions)

    def test_full_pipeline_malware_medium_risk(self):
        """Integration: Medium-risk malware goes through full engine."""
        hash_ioc = IoC(
            ioc_type="hash_sha256",
            value="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            context="test",
        )
        alert = _make_alert(
            alert_type=AlertType.MALWARE_DETECTED,
            risk_score=65.0,
            iocs=[hash_ioc],
        )
        actions = self.engine.execute(alert)
        self.assertTrue(any("quarantine_hash" in a for a in actions))
        self.assertEqual(alert.playbook_name, "malware_response")


if __name__ == "__main__":
    unittest.main()
