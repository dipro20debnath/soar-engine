"""SOAR Engine - Containment & Approval Workflow Tests

Tests cover:
    1. SimulatedFirewall (block, unblock, blocklist, action log)
    2. SimulatedAWSIsolator (isolate, restore, isolation list)
    3. NotificationService (send alert, history)
    4. PlaybookEngine containment integration (block_ip -> firewall)
    5. Approval workflow (pending, approve, reject)
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
from app.containment.firewall import SimulatedFirewall
from app.containment.aws_isolator import SimulatedAWSIsolator
from app.containment.notification import NotificationService
from app.services.playbook_engine import PlaybookEngine


# ── Helpers ───────────────────────────────────────────

def _make_alert(
    alert_type: AlertType = AlertType.BRUTE_FORCE,
    risk_score: Optional[float] = 50.0,
    source_ip: str = "103.24.55.12",
    target_host: str = "web-server-01",
) -> NormalizedAlert:
    """Create a test NormalizedAlert."""
    return NormalizedAlert(
        timestamp=datetime(2026, 6, 19, 10, 0, 0, tzinfo=timezone.utc),
        alert_type=alert_type,
        severity=AlertSeverity.HIGH,
        status=AlertStatus.ENRICHED,
        source_ip=source_ip,
        target_host=target_host,
        risk_score=risk_score,
        description="Test alert",
    )


# ═════════════════════════════════════════════════════
# SimulatedFirewall Tests
# ═════════════════════════════════════════════════════

class TestSimulatedFirewall(unittest.TestCase):
    """Test the in-memory firewall blocklist."""

    def setUp(self):
        self.fw = SimulatedFirewall()

    def test_block_ip_success(self):
        result = self.fw.block_ip("1.2.3.4", reason="test")
        self.assertTrue(result)
        self.assertTrue(self.fw.is_blocked("1.2.3.4"))

    def test_block_ip_already_blocked(self):
        self.fw.block_ip("1.2.3.4")
        result = self.fw.block_ip("1.2.3.4")
        self.assertFalse(result)

    def test_unblock_ip_success(self):
        self.fw.block_ip("1.2.3.4")
        result = self.fw.unblock_ip("1.2.3.4")
        self.assertTrue(result)
        self.assertFalse(self.fw.is_blocked("1.2.3.4"))

    def test_unblock_ip_not_found(self):
        result = self.fw.unblock_ip("1.2.3.4")
        self.assertFalse(result)

    def test_get_blocklist(self):
        self.fw.block_ip("1.2.3.4", reason="brute_force")
        self.fw.block_ip("5.6.7.8", reason="port_scan")
        blocklist = self.fw.get_blocklist()
        self.assertEqual(len(blocklist), 2)
        self.assertIn("1.2.3.4", blocklist)
        self.assertIn("5.6.7.8", blocklist)

    def test_blocked_count(self):
        self.assertEqual(self.fw.blocked_count, 0)
        self.fw.block_ip("1.2.3.4")
        self.fw.block_ip("5.6.7.8")
        self.assertEqual(self.fw.blocked_count, 2)
        self.fw.unblock_ip("1.2.3.4")
        self.assertEqual(self.fw.blocked_count, 1)

    def test_action_log_records_blocks(self):
        self.fw.block_ip("1.2.3.4", reason="test")
        log = self.fw.get_action_log()
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["action"], "block")
        self.assertEqual(log[0]["ip_address"], "1.2.3.4")

    def test_action_log_records_unblocks(self):
        self.fw.block_ip("1.2.3.4")
        self.fw.unblock_ip("1.2.3.4", reason="cleared")
        log = self.fw.get_action_log()
        self.assertEqual(len(log), 2)
        # Newest first
        self.assertEqual(log[0]["action"], "unblock")

    def test_clear(self):
        self.fw.block_ip("1.2.3.4")
        self.fw.clear()
        self.assertEqual(self.fw.blocked_count, 0)
        self.assertEqual(len(self.fw.get_action_log()), 0)


# ═════════════════════════════════════════════════════
# SimulatedAWSIsolator Tests
# ═════════════════════════════════════════════════════

class TestSimulatedAWSIsolator(unittest.TestCase):
    """Test the in-memory AWS EC2 isolator."""

    def setUp(self):
        self.iso = SimulatedAWSIsolator()

    def test_isolate_instance_success(self):
        result = self.iso.isolate_instance("web-server-01")
        self.assertTrue(result)
        self.assertTrue(self.iso.is_isolated("web-server-01"))

    def test_isolate_already_isolated(self):
        self.iso.isolate_instance("web-server-01")
        result = self.iso.isolate_instance("web-server-01")
        self.assertFalse(result)

    def test_restore_instance_success(self):
        self.iso.isolate_instance("web-server-01")
        result = self.iso.restore_instance("web-server-01")
        self.assertTrue(result)
        self.assertFalse(self.iso.is_isolated("web-server-01"))

    def test_restore_not_found(self):
        result = self.iso.restore_instance("web-server-01")
        self.assertFalse(result)

    def test_get_isolated_instances(self):
        self.iso.isolate_instance("web-01")
        self.iso.isolate_instance("web-02")
        instances = self.iso.get_isolated_instances()
        self.assertEqual(len(instances), 2)
        self.assertIn("web-01", instances)

    def test_isolated_count(self):
        self.assertEqual(self.iso.isolated_count, 0)
        self.iso.isolate_instance("web-01")
        self.assertEqual(self.iso.isolated_count, 1)

    def test_action_log(self):
        self.iso.isolate_instance("web-01", reason="malware")
        log = self.iso.get_action_log()
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["action"], "isolate")
        self.assertEqual(log[0]["instance_id"], "web-01")

    def test_clear(self):
        self.iso.isolate_instance("web-01")
        self.iso.clear()
        self.assertEqual(self.iso.isolated_count, 0)


# ═════════════════════════════════════════════════════
# NotificationService Tests
# ═════════════════════════════════════════════════════

class TestNotificationService(unittest.TestCase):
    """Test the simulated notification service."""

    def setUp(self):
        self.ns = NotificationService()

    def test_send_alert(self):
        result = self.ns.send_alert("Test message", "info")
        self.assertTrue(result)
        self.assertEqual(self.ns.total_sent, 1)

    def test_send_critical_alert(self):
        result = self.ns.send_alert("Critical!", "critical", alert_id="abc")
        self.assertTrue(result)

    def test_send_playbook_notification(self):
        result = self.ns.send_playbook_notification(
            alert_id="abc-123",
            playbook_name="brute_force_response",
            actions=["block_ip:1.2.3.4"],
            risk_score=85.0,
        )
        self.assertTrue(result)
        self.assertEqual(self.ns.total_sent, 1)

    def test_send_approval_request(self):
        result = self.ns.send_approval_request(
            alert_id="abc-123",
            pending_actions=["isolate_host:web-01"],
            risk_score=95.0,
        )
        self.assertTrue(result)
        history = self.ns.get_history()
        self.assertTrue(any("APPROVAL" in n["message"] for n in history))

    def test_history_newest_first(self):
        self.ns.send_alert("First", "info")
        self.ns.send_alert("Second", "warning")
        self.ns.send_alert("Third", "critical")
        history = self.ns.get_history()
        self.assertEqual(len(history), 3)
        self.assertEqual(history[0]["message"], "Third")

    def test_clear_history(self):
        self.ns.send_alert("Test", "info")
        self.ns.clear_history()
        self.assertEqual(self.ns.total_sent, 0)


# ═════════════════════════════════════════════════════
# PlaybookEngine Containment Integration Tests
# ═════════════════════════════════════════════════════

class TestPlaybookEngineContainment(unittest.TestCase):
    """Test that PlaybookEngine actually triggers containment modules."""

    def setUp(self):
        self.engine = PlaybookEngine()
        # Reset containment state for each test
        from app.containment.firewall import firewall
        from app.containment.aws_isolator import aws_isolator
        from app.containment.notification import notification_service
        firewall.clear()
        aws_isolator.clear()
        notification_service.clear_history()

    def test_high_risk_brute_force_blocks_in_firewall(self):
        """Brute force with risk > 75 should block the IP in the firewall."""
        from app.containment.firewall import firewall

        alert = _make_alert(
            alert_type=AlertType.BRUTE_FORCE,
            risk_score=85.0,
            source_ip="185.220.101.45",
        )
        self.engine.execute(alert)

        self.assertTrue(firewall.is_blocked("185.220.101.45"))

    def test_high_risk_malware_isolates_host(self):
        """Malware with risk > 80 should isolate the host."""
        from app.containment.aws_isolator import aws_isolator

        alert = _make_alert(
            alert_type=AlertType.MALWARE_DETECTED,
            risk_score=85.0,
            target_host="compromised-server",
        )
        self.engine.execute(alert)

        self.assertTrue(aws_isolator.is_isolated("compromised-server"))

    def test_playbook_sends_notifications(self):
        """Playbook execution should send SOC notifications."""
        from app.containment.notification import notification_service

        alert = _make_alert(risk_score=50.0)
        self.engine.execute(alert)

        # Should have at least one notification (playbook result + SOC notify)
        self.assertGreater(notification_service.total_sent, 0)

    def test_low_risk_does_not_block(self):
        """Low risk alerts should NOT trigger containment actions."""
        from app.containment.firewall import firewall

        alert = _make_alert(risk_score=15.0)
        self.engine.execute(alert)

        self.assertEqual(firewall.blocked_count, 0)

    def test_alert_status_set_to_responded(self):
        """After playbook execution, alert status should be RESPONDED."""
        alert = _make_alert(risk_score=50.0)
        self.engine.execute(alert)
        self.assertEqual(alert.status, AlertStatus.RESPONDED)


# ═════════════════════════════════════════════════════
# Approval Workflow Tests
# ═════════════════════════════════════════════════════

class TestApprovalWorkflow(unittest.TestCase):
    """Test the human approval workflow for high-impact actions."""

    def setUp(self):
        self.engine = PlaybookEngine()
        from app.containment.firewall import firewall
        from app.containment.aws_isolator import aws_isolator
        from app.containment.notification import notification_service
        firewall.clear()
        aws_isolator.clear()
        notification_service.clear_history()

    def test_very_high_risk_triggers_approval(self):
        """Risk > 90 with high-impact action should require approval."""
        alert = _make_alert(
            alert_type=AlertType.MALWARE_DETECTED,
            risk_score=95.0,
            target_host="critical-server",
        )
        actions = self.engine.execute(alert)

        # Alert should be in pending approval state
        self.assertEqual(alert.status, AlertStatus.PENDING_APPROVAL)
        self.assertTrue(any("pending_approval" in a for a in actions))

        # Should have a pending approval entry
        pending = self.engine.get_pending_approvals()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["alert_id"], alert.alert_id)

    def test_very_high_risk_host_not_immediately_isolated(self):
        """Host should NOT be isolated until approved."""
        from app.containment.aws_isolator import aws_isolator

        alert = _make_alert(
            alert_type=AlertType.MALWARE_DETECTED,
            risk_score=95.0,
            target_host="critical-server",
        )
        self.engine.execute(alert)

        # Host should NOT be isolated yet
        self.assertFalse(aws_isolator.is_isolated("critical-server"))

    def test_approve_executes_deferred_actions(self):
        """Approving an alert should execute the deferred containment actions."""
        from app.containment.aws_isolator import aws_isolator

        alert = _make_alert(
            alert_type=AlertType.MALWARE_DETECTED,
            risk_score=95.0,
            target_host="critical-server",
        )
        self.engine.execute(alert)

        # Approve
        result = self.engine.approve_alert(alert.alert_id)
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "approved")

        # Host should now be isolated
        self.assertTrue(aws_isolator.is_isolated("critical-server"))

        # Pending list should be empty
        self.assertEqual(len(self.engine.get_pending_approvals()), 0)

    def test_reject_discards_deferred_actions(self):
        """Rejecting an alert should discard the deferred containment actions."""
        from app.containment.aws_isolator import aws_isolator

        alert = _make_alert(
            alert_type=AlertType.MALWARE_DETECTED,
            risk_score=95.0,
            target_host="critical-server",
        )
        self.engine.execute(alert)

        # Reject
        result = self.engine.reject_alert(alert.alert_id)
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "rejected")

        # Host should NOT be isolated
        self.assertFalse(aws_isolator.is_isolated("critical-server"))

        # Pending list should be empty
        self.assertEqual(len(self.engine.get_pending_approvals()), 0)

    def test_approve_nonexistent_returns_none(self):
        result = self.engine.approve_alert("nonexistent-id")
        self.assertIsNone(result)

    def test_reject_nonexistent_returns_none(self):
        result = self.engine.reject_alert("nonexistent-id")
        self.assertIsNone(result)

    def test_risk_below_90_does_not_need_approval(self):
        """Risk <= 90 should NOT trigger the approval workflow."""
        alert = _make_alert(
            alert_type=AlertType.MALWARE_DETECTED,
            risk_score=85.0,
            target_host="server-01",
        )
        self.engine.execute(alert)

        # Should be responded, not pending approval
        self.assertEqual(alert.status, AlertStatus.RESPONDED)
        self.assertEqual(len(self.engine.get_pending_approvals()), 0)

    def test_brute_force_high_risk_no_approval_needed(self):
        """Brute force blocks IP (not high-impact), so no approval needed even at 95."""
        alert = _make_alert(
            alert_type=AlertType.BRUTE_FORCE,
            risk_score=95.0,
        )
        actions = self.engine.execute(alert)

        # block_ip is NOT a high-impact action, so no approval needed
        self.assertEqual(alert.status, AlertStatus.RESPONDED)
        self.assertFalse(any("pending_approval" in a for a in actions))

    def test_suspicious_login_very_high_risk_needs_approval(self):
        """Suspicious login with lock_account at risk > 90 needs approval."""
        alert = _make_alert(
            alert_type=AlertType.SUSPICIOUS_LOGIN,
            risk_score=95.0,
        )
        actions = self.engine.execute(alert)

        # lock_account IS a high-impact action
        self.assertEqual(alert.status, AlertStatus.PENDING_APPROVAL)
        self.assertTrue(any("pending_approval" in a for a in actions))

    def test_approval_records_in_history(self):
        """Approval should be recorded in execution history."""
        alert = _make_alert(
            alert_type=AlertType.MALWARE_DETECTED,
            risk_score=95.0,
        )
        self.engine.execute(alert)
        self.engine.approve_alert(alert.alert_id)

        history = self.engine.get_history()
        statuses = [h["status"] for h in history]
        self.assertIn("approved", statuses)
        self.assertIn("pending_approval", statuses)


if __name__ == "__main__":
    unittest.main()
