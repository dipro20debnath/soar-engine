"""SOAR Engine - Playbook Engine & Playbook Unit Tests

Tests cover:
    1. BasePlaybook interface contract
    2. Individual playbook action logic at different risk levels
    3. Enrichment-driven escalation and tagging
    4. PlaybookEngine alert-to-playbook mapping (5 types + default)
    5. Default fallback for unmapped alert types
    6. Alert mutation (playbook_name, response_actions populated)
    7. Execution history tracking
    8. Port scan and data exfiltration playbooks
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
from app.models.enrichment import (
    EnrichmentResult,
    IPReputation,
    FileHashResult,
)
from app.playbooks.base import BasePlaybook
from app.playbooks.default import DefaultPlaybook
from app.playbooks.brute_force import BruteForcePlaybook
from app.playbooks.malware_detected import MalwareDetectedPlaybook
from app.playbooks.suspicious_login import SuspiciousLoginPlaybook
from app.playbooks.port_scan import PortScanPlaybook
from app.playbooks.data_exfiltration import DataExfiltrationPlaybook
from app.services.playbook_engine import PlaybookEngine


# ── Helpers ───────────────────────────────────────────

def _make_alert(
    alert_type: AlertType = AlertType.UNKNOWN,
    severity: AlertSeverity = AlertSeverity.MEDIUM,
    risk_score: Optional[float] = None,
    source_ip: str = "103.24.55.12",
    dest_ip: Optional[str] = None,
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
        dest_ip=dest_ip,
        target_host=target_host,
        risk_score=risk_score,
        description="Test alert",
        iocs=iocs or [],
    )


def _make_ip_enrichment(
    alert_id: str = "test-id",
    ip_address: str = "103.24.55.12",
    abuse_score: int = 50,
    country: str = "US",
    is_tor: bool = False,
    total_reports: int = 10,
    isp: str = "DigitalOcean",
) -> EnrichmentResult:
    """Create a test EnrichmentResult with IP reputation data."""
    return EnrichmentResult(
        alert_id=alert_id,
        ip_results=[
            IPReputation(
                ip_address=ip_address,
                abuse_confidence_score=abuse_score,
                country_code=country,
                is_tor=is_tor,
                total_reports=total_reports,
                isp=isp,
            )
        ],
    )


def _make_hash_enrichment(
    alert_id: str = "test-id",
    file_hash: str = "abcdef1234567890" * 4,
    is_malicious: bool = True,
    malware_family: Optional[str] = "Emotet",
    detection_ratio: str = "45/72",
) -> EnrichmentResult:
    """Create a test EnrichmentResult with VirusTotal hash data."""
    return EnrichmentResult(
        alert_id=alert_id,
        hash_results=[
            FileHashResult(
                file_hash=file_hash,
                is_malicious=is_malicious,
                malware_family=malware_family,
                detection_ratio=detection_ratio,
            )
        ],
    )


# ═════════════════════════════════════════════════════
# BasePlaybook Tests
# ═════════════════════════════════════════════════════

class TestBasePlaybook(unittest.TestCase):
    """Test that BasePlaybook enforces the abstract interface."""

    def test_cannot_instantiate_directly(self):
        """BasePlaybook is abstract - direct instantiation should fail."""
        with self.assertRaises(TypeError):
            BasePlaybook()

    def test_risk_score_helper_with_score(self):
        """_get_risk_score returns the alert's risk score when present."""
        playbook = DefaultPlaybook()
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
    """Test brute-force response playbook with enrichment."""

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

    def test_enrichment_escalation_high_abuse_score(self):
        """Medium-risk alert should be escalated if AbuseIPDB score >= 90."""
        alert = _make_alert(
            alert_type=AlertType.BRUTE_FORCE,
            risk_score=50.0,
            source_ip="103.24.55.12",
        )
        enrichment = _make_ip_enrichment(abuse_score=95)
        actions = self.playbook.execute(alert, enrichment)
        # Should be escalated to high risk -> block IP
        self.assertTrue(any("enrichment_escalation" in a for a in actions))
        self.assertIn("block_ip:103.24.55.12", actions)

    def test_tor_exit_node_tagged(self):
        """Tor exit node IPs should get a tor_exit_node tag."""
        alert = _make_alert(
            alert_type=AlertType.BRUTE_FORCE, risk_score=50.0
        )
        enrichment = _make_ip_enrichment(is_tor=True, abuse_score=50)
        actions = self.playbook.execute(alert, enrichment)
        self.assertTrue(any("tor_exit_node" in a for a in actions))

    def test_repeat_offender_tagged(self):
        """IPs with >100 reports should get repeat_offender tag."""
        alert = _make_alert(
            alert_type=AlertType.BRUTE_FORCE, risk_score=50.0
        )
        enrichment = _make_ip_enrichment(total_reports=150)
        actions = self.playbook.execute(alert, enrichment)
        self.assertTrue(any("repeat_offender" in a for a in actions))

    def test_high_risk_country_tagged(self):
        """IPs from high-risk countries should get a tag."""
        alert = _make_alert(
            alert_type=AlertType.BRUTE_FORCE, risk_score=50.0
        )
        enrichment = _make_ip_enrichment(country="RU")
        actions = self.playbook.execute(alert, enrichment)
        self.assertTrue(any("high_risk_country:RU" in a for a in actions))

    def test_no_enrichment_still_works(self):
        """Playbook should work fine without enrichment data."""
        alert = _make_alert(
            alert_type=AlertType.BRUTE_FORCE, risk_score=85.0
        )
        actions = self.playbook.execute(alert, None)
        self.assertIn("block_ip:103.24.55.12", actions)


# ═════════════════════════════════════════════════════
# MalwareDetectedPlaybook Tests
# ═════════════════════════════════════════════════════

class TestMalwareDetectedPlaybook(unittest.TestCase):
    """Test malware detection response playbook with enrichment."""

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

    def test_critical_malware_family_escalates(self):
        """Known critical malware families should escalate to high risk."""
        alert = _make_alert(
            alert_type=AlertType.MALWARE_DETECTED,
            risk_score=40.0,
            iocs=[self.hash_ioc],
        )
        enrichment = _make_hash_enrichment(malware_family="Emotet")
        actions = self.playbook.execute(alert, enrichment)
        # Should be escalated to high risk
        self.assertTrue(any("enrichment_escalation" in a for a in actions))
        self.assertIn("isolate_host:web-server-01", actions)

    def test_vt_confirmed_malware_tagged(self):
        """VirusTotal-confirmed malware should get a tag."""
        alert = _make_alert(
            alert_type=AlertType.MALWARE_DETECTED,
            risk_score=65.0,
            iocs=[self.hash_ioc],
        )
        enrichment = _make_hash_enrichment(
            is_malicious=True, malware_family="TrickBot"
        )
        actions = self.playbook.execute(alert, enrichment)
        self.assertTrue(any("vt_confirmed_malware" in a for a in actions))
        self.assertTrue(any("malware_family:TrickBot" in a for a in actions))

    def test_high_detection_ratio_escalates(self):
        """Very high detection ratio should escalate low-risk to medium."""
        alert = _make_alert(
            alert_type=AlertType.MALWARE_DETECTED,
            risk_score=30.0,
            iocs=[self.hash_ioc],
        )
        enrichment = _make_hash_enrichment(
            is_malicious=False,
            malware_family=None,
            detection_ratio="55/72",
        )
        actions = self.playbook.execute(alert, enrichment)
        # Should be escalated to at least medium risk
        self.assertTrue(any("enrichment_escalation" in a for a in actions))
        self.assertTrue(any("quarantine_hash" in a for a in actions))

    def test_c2_urls_blocked_at_high_risk(self):
        """C2 URLs in IoCs should be blocked at high risk."""
        url_ioc = IoC(ioc_type="url", value="http://evil.com/c2", context="c2")
        alert = _make_alert(
            alert_type=AlertType.MALWARE_DETECTED,
            risk_score=90.0,
            iocs=[self.hash_ioc, url_ioc],
        )
        actions = self.playbook.execute(alert)
        self.assertIn("block_c2_url:http://evil.com/c2", actions)


# ═════════════════════════════════════════════════════
# SuspiciousLoginPlaybook Tests
# ═════════════════════════════════════════════════════

class TestSuspiciousLoginPlaybook(unittest.TestCase):
    """Test suspicious login response playbook with enrichment."""

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

    def test_high_risk_also_resets_password(self):
        """High risk suspicious login should also force password reset."""
        alert = _make_alert(
            alert_type=AlertType.SUSPICIOUS_LOGIN, risk_score=85.0
        )
        actions = self.playbook.execute(alert)
        self.assertIn("force_password_reset", actions)

    def test_tor_escalation(self):
        """Login from Tor should escalate low-risk to at least medium."""
        alert = _make_alert(
            alert_type=AlertType.SUSPICIOUS_LOGIN, risk_score=20.0
        )
        enrichment = _make_ip_enrichment(is_tor=True, abuse_score=30)
        actions = self.playbook.execute(alert, enrichment)
        # Should be escalated to at least medium tier
        self.assertTrue(any("enrichment_escalation" in a for a in actions))
        self.assertIn("force_password_reset", actions)

    def test_high_abuse_score_escalation(self):
        """High abuse score should escalate to high risk."""
        alert = _make_alert(
            alert_type=AlertType.SUSPICIOUS_LOGIN,
            risk_score=50.0,
            source_ip="103.24.55.12",
        )
        enrichment = _make_ip_enrichment(abuse_score=90)
        actions = self.playbook.execute(alert, enrichment)
        self.assertTrue(any("enrichment_escalation" in a for a in actions))
        self.assertIn("lock_account", actions)

    def test_suspicious_country_tagged(self):
        """Login from suspicious country should get a tag."""
        alert = _make_alert(
            alert_type=AlertType.SUSPICIOUS_LOGIN, risk_score=50.0
        )
        enrichment = _make_ip_enrichment(country="CN")
        actions = self.playbook.execute(alert, enrichment)
        self.assertTrue(any("suspicious_country:CN" in a for a in actions))

    def test_login_country_tagged(self):
        """Login country should always be tagged when available."""
        alert = _make_alert(
            alert_type=AlertType.SUSPICIOUS_LOGIN, risk_score=50.0
        )
        enrichment = _make_ip_enrichment(country="US")
        actions = self.playbook.execute(alert, enrichment)
        self.assertTrue(any("login_country:US" in a for a in actions))


# ═════════════════════════════════════════════════════
# PortScanPlaybook Tests
# ═════════════════════════════════════════════════════

class TestPortScanPlaybook(unittest.TestCase):
    """Test port scan response playbook."""

    def setUp(self):
        self.playbook = PortScanPlaybook()

    def test_name_and_description(self):
        self.assertEqual(self.playbook.name, "port_scan_response")
        self.assertIn("port", self.playbook.description.lower())

    def test_low_risk_logs_only(self):
        alert = _make_alert(alert_type=AlertType.PORT_SCAN, risk_score=20.0)
        actions = self.playbook.execute(alert)
        self.assertEqual(actions, ["log_only"])

    def test_medium_risk_rate_limits(self):
        alert = _make_alert(
            alert_type=AlertType.PORT_SCAN,
            risk_score=55.0,
            source_ip="91.198.174.192",
        )
        actions = self.playbook.execute(alert)
        self.assertIn("rate_limit_ip:91.198.174.192", actions)
        self.assertTrue(any("watchlist" in a for a in actions))

    def test_high_risk_blocks_ip(self):
        alert = _make_alert(
            alert_type=AlertType.PORT_SCAN,
            risk_score=80.0,
            source_ip="91.198.174.192",
        )
        actions = self.playbook.execute(alert)
        self.assertIn("block_ip:91.198.174.192", actions)
        self.assertIn("create_incident_ticket", actions)

    def test_known_scanner_escalation(self):
        """Known scanner with high abuse score should be escalated."""
        alert = _make_alert(
            alert_type=AlertType.PORT_SCAN,
            risk_score=50.0,
            source_ip="103.24.55.12",
        )
        enrichment = _make_ip_enrichment(abuse_score=85)
        actions = self.playbook.execute(alert, enrichment)
        self.assertTrue(any("enrichment_escalation" in a for a in actions))
        self.assertIn("block_ip:103.24.55.12", actions)

    def test_known_scanner_tagged(self):
        """IPs with many reports should get a known_scanner tag."""
        alert = _make_alert(
            alert_type=AlertType.PORT_SCAN, risk_score=50.0
        )
        enrichment = _make_ip_enrichment(total_reports=60)
        actions = self.playbook.execute(alert, enrichment)
        self.assertTrue(any("known_scanner" in a for a in actions))

    def test_no_enrichment_still_works(self):
        alert = _make_alert(
            alert_type=AlertType.PORT_SCAN, risk_score=80.0
        )
        actions = self.playbook.execute(alert, None)
        self.assertIn("block_ip:103.24.55.12", actions)


# ═════════════════════════════════════════════════════
# DataExfiltrationPlaybook Tests
# ═════════════════════════════════════════════════════

class TestDataExfiltrationPlaybook(unittest.TestCase):
    """Test data exfiltration response playbook."""

    def setUp(self):
        self.playbook = DataExfiltrationPlaybook()

    def test_name_and_description(self):
        self.assertEqual(self.playbook.name, "data_exfiltration_response")
        self.assertIn("exfiltration", self.playbook.description.lower())

    def test_low_risk_monitors(self):
        alert = _make_alert(
            alert_type=AlertType.DATA_EXFILTRATION, risk_score=20.0
        )
        actions = self.playbook.execute(alert)
        self.assertIn("log_and_monitor", actions)
        self.assertTrue(any("monitor_traffic" in a for a in actions))

    def test_medium_risk_throttles(self):
        alert = _make_alert(
            alert_type=AlertType.DATA_EXFILTRATION,
            risk_score=55.0,
            dest_ip="185.100.87.202",
        )
        actions = self.playbook.execute(alert)
        self.assertTrue(any("throttle_outbound" in a for a in actions))
        self.assertIn("create_incident_ticket", actions)
        self.assertIn("notify_soc:warning", actions)

    def test_high_risk_isolates_host(self):
        alert = _make_alert(
            alert_type=AlertType.DATA_EXFILTRATION,
            risk_score=85.0,
            dest_ip="185.100.87.202",
        )
        actions = self.playbook.execute(alert)
        self.assertIn("isolate_host:web-server-01", actions)
        self.assertIn("block_ip:185.100.87.202", actions)
        self.assertIn("notify_soc:critical", actions)

    def test_c2_urls_force_high_risk(self):
        """Presence of C2 URLs should force escalation to high risk."""
        url_ioc = IoC(ioc_type="url", value="http://evil.com/exfil", context="c2")
        alert = _make_alert(
            alert_type=AlertType.DATA_EXFILTRATION,
            risk_score=30.0,
            iocs=[url_ioc],
        )
        actions = self.playbook.execute(alert)
        self.assertTrue(any("enrichment_escalation" in a for a in actions))
        self.assertIn("isolate_host:web-server-01", actions)
        self.assertIn("block_c2_url:http://evil.com/exfil", actions)

    def test_malicious_dest_ip_escalates(self):
        """Malicious destination IP should escalate to high risk."""
        alert = _make_alert(
            alert_type=AlertType.DATA_EXFILTRATION,
            risk_score=50.0,
            source_ip="10.0.1.50",
            dest_ip="185.100.87.202",
        )
        enrichment = EnrichmentResult(
            alert_id="test",
            ip_results=[
                IPReputation(
                    ip_address="185.100.87.202",
                    abuse_confidence_score=80,
                )
            ],
        )
        actions = self.playbook.execute(alert, enrichment)
        self.assertTrue(any("enrichment_escalation" in a for a in actions))
        self.assertIn("isolate_host:web-server-01", actions)

    def test_c2_communication_tagged(self):
        """C2 URLs should be tagged with count."""
        url1 = IoC(ioc_type="url", value="http://evil.com/1", context="c2")
        url2 = IoC(ioc_type="url", value="http://evil.com/2", context="c2")
        alert = _make_alert(
            alert_type=AlertType.DATA_EXFILTRATION,
            risk_score=85.0,
            iocs=[url1, url2],
        )
        actions = self.playbook.execute(alert)
        self.assertTrue(any("c2_communication:2_urls" in a for a in actions))

    def test_no_enrichment_still_works(self):
        alert = _make_alert(
            alert_type=AlertType.DATA_EXFILTRATION, risk_score=85.0
        )
        actions = self.playbook.execute(alert, None)
        self.assertIn("isolate_host:web-server-01", actions)


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

    def test_maps_port_scan_to_playbook(self):
        pb = self.engine.get_playbook(AlertType.PORT_SCAN)
        self.assertIsInstance(pb, PortScanPlaybook)

    def test_maps_data_exfiltration_to_playbook(self):
        pb = self.engine.get_playbook(AlertType.DATA_EXFILTRATION)
        self.assertIsInstance(pb, DataExfiltrationPlaybook)

    def test_unknown_type_uses_default(self):
        pb = self.engine.get_playbook(AlertType.UNKNOWN)
        self.assertIsInstance(pb, DefaultPlaybook)

    def test_phishing_uses_default(self):
        pb = self.engine.get_playbook(AlertType.PHISHING)
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
        self.assertIn("port_scan", registered)
        self.assertIn("data_exfiltration", registered)
        self.assertIn("_default", registered)

    def test_execute_default_for_unknown_type(self):
        """Unknown alert type should trigger the default playbook."""
        alert = _make_alert(alert_type=AlertType.UNKNOWN, risk_score=55.0)
        actions = self.engine.execute(alert)
        self.assertEqual(alert.playbook_name, "default_triage")
        self.assertIn("assign_triage_ticket", actions)

    def test_execute_port_scan_playbook(self):
        """Port scan should now use dedicated playbook, not default."""
        alert = _make_alert(alert_type=AlertType.PORT_SCAN, risk_score=80.0)
        actions = self.engine.execute(alert)
        self.assertEqual(alert.playbook_name, "port_scan_response")
        self.assertIn("block_ip:103.24.55.12", actions)

    def test_execute_data_exfiltration_playbook(self):
        """Data exfiltration should use dedicated playbook."""
        alert = _make_alert(
            alert_type=AlertType.DATA_EXFILTRATION,
            risk_score=85.0,
            dest_ip="185.100.87.202",
        )
        actions = self.engine.execute(alert)
        self.assertEqual(alert.playbook_name, "data_exfiltration_response")
        self.assertIn("isolate_host:web-server-01", actions)

    def test_full_pipeline_brute_force_with_enrichment(self):
        """Integration: High-risk brute force with enrichment through engine."""
        alert = _make_alert(
            alert_type=AlertType.BRUTE_FORCE,
            risk_score=50.0,
            source_ip="185.220.101.45",
        )
        enrichment = _make_ip_enrichment(
            ip_address="185.220.101.45",
            abuse_score=95,
            country="RU",
            is_tor=True,
            total_reports=200,
        )
        actions = self.engine.execute(alert, enrichment)
        # Should be escalated and have multiple tags
        self.assertIn("block_ip:185.220.101.45", actions)
        self.assertTrue(any("tor_exit_node" in a for a in actions))
        self.assertTrue(any("repeat_offender" in a for a in actions))
        self.assertTrue(any("high_risk_country:RU" in a for a in actions))

    def test_full_pipeline_malware_with_enrichment(self):
        """Integration: Malware with critical family through engine."""
        hash_ioc = IoC(
            ioc_type="hash_sha256",
            value="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            context="test",
        )
        alert = _make_alert(
            alert_type=AlertType.MALWARE_DETECTED,
            risk_score=40.0,
            iocs=[hash_ioc],
        )
        enrichment = _make_hash_enrichment(malware_family="Emotet")
        actions = self.engine.execute(alert, enrichment)
        self.assertEqual(alert.playbook_name, "malware_response")
        self.assertIn("isolate_host:web-server-01", actions)
        self.assertTrue(any("malware_family:Emotet" in a for a in actions))


if __name__ == "__main__":
    unittest.main()
