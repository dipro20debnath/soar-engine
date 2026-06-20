"""SOAR Engine - Full Pipeline Integration Tests (Day 13)

End-to-end tests that verify the complete SOAR pipeline works correctly:
    Receive → Normalize → Enrich → Score → Playbook → Contain → Store

These tests use FastAPI's TestClient to hit real API endpoints and verify
that alerts flow through the entire system correctly.

Also includes edge case tests for error handling and boundary conditions.
"""

import unittest
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.main import app
from app.db.store import alert_store
from app.containment.firewall import firewall
from app.containment.aws_isolator import aws_isolator
from app.containment.notification import notification_service
from app.services.playbook_engine import playbook_engine
from app.models.alert import AlertType, AlertSeverity, AlertStatus


client = TestClient(app)


class _IntegrationTestBase(unittest.TestCase):
    """Base class that resets all global state before each test."""

    def setUp(self):
        alert_store.clear()
        firewall.clear()
        aws_isolator.clear()
        notification_service.clear_history()
        playbook_engine.clear_history()
        playbook_engine._pending_approval.clear()


# ═════════════════════════════════════════════════════
# API Health & Root Endpoint Tests
# ═════════════════════════════════════════════════════

class TestHealthEndpoints(_IntegrationTestBase):
    """Test the health check and root endpoints."""

    def test_root_endpoint(self):
        response = client.get("/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "operational")
        self.assertIn("endpoints", data)
        self.assertIn("playbooks", data["endpoints"])

    def test_health_check(self):
        response = client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "healthy")
        self.assertIn("enrichment", data)


# ═════════════════════════════════════════════════════
# Webhook Pipeline Integration Tests
# ═════════════════════════════════════════════════════

class TestWebhookPipeline(_IntegrationTestBase):
    """End-to-end tests: raw alert → stored & processed."""

    def _send_alert(self, payload: dict, source: str = "generic") -> dict:
        """Helper: send an alert via POST /api/alerts."""
        response = client.post(
            "/api/alerts",
            json={"source": source, "payload": payload},
        )
        self.assertEqual(response.status_code, 201)
        return response.json()

    def test_generic_brute_force_alert(self):
        """A generic brute force alert should be normalized, enriched, and scored."""
        data = self._send_alert({
            "alert_type": "brute_force",
            "severity": "high",
            "source_ip": "185.220.101.45",
            "target_host": "web-server-01",
            "description": "50 failed SSH login attempts in 60 seconds",
        })
        self.assertTrue(data["success"])
        self.assertEqual(data["alert_type"], "brute_force")
        self.assertEqual(data["severity"], "high")
        self.assertIsNotNone(data["alert_id"])

    def test_splunk_malware_alert(self):
        """A Splunk-format malware alert should normalize correctly."""
        data = self._send_alert(
            {
                "result": {
                    "alert_type": "malware_detected",
                    "severity": "critical",
                    "src_ip": "103.24.55.12",
                    "dest_host": "db-primary-01",
                    "file_hash": "e99a18c428cb38d5f260853678922e03",
                    "description": "Known malware hash detected",
                }
            },
            source="splunk",
        )
        self.assertTrue(data["success"])
        self.assertEqual(data["alert_type"], "malware_detected")

    def test_elastic_suspicious_login(self):
        """An Elastic-format suspicious login should normalize correctly."""
        data = self._send_alert(
            {
                "_source": {
                    "source": {"ip": "77.88.55.66"},
                    "host": {"name": "api-server-02"},
                    "message": "Login from unusual location",
                },
                "alert_type": "suspicious_login",
                "severity": "medium",
            },
            source="elastic",
        )
        self.assertTrue(data["success"])
        self.assertEqual(data["alert_type"], "suspicious_login")

    def test_alert_stored_after_processing(self):
        """Alert should be retrievable from the store after processing."""
        data = self._send_alert({
            "alert_type": "port_scan",
            "severity": "medium",
            "source_ip": "91.198.174.192",
            "description": "Network port scan detected",
        })
        alert_id = data["alert_id"]

        # Should be retrievable via GET /api/alerts/{id}
        response = client.get(f"/api/alerts/{alert_id}")
        self.assertEqual(response.status_code, 200)
        alert = response.json()
        self.assertEqual(alert["alert_id"], alert_id)
        self.assertEqual(alert["alert_type"], "port_scan")

    def test_alert_appears_in_list(self):
        """Alert should appear in the alerts list endpoint."""
        self._send_alert({
            "alert_type": "brute_force",
            "severity": "high",
            "source_ip": "185.220.101.45",
        })

        response = client.get("/api/alerts")
        self.assertEqual(response.status_code, 200)
        alerts = response.json()
        self.assertEqual(len(alerts), 1)

    def test_stats_updated_after_alert(self):
        """Stats should reflect newly processed alerts."""
        self._send_alert({
            "alert_type": "brute_force",
            "severity": "high",
            "source_ip": "185.220.101.45",
        })

        response = client.get("/api/stats")
        self.assertEqual(response.status_code, 200)
        stats = response.json()
        self.assertEqual(stats["total_alerts"], 1)
        self.assertIn("brute_force", stats["by_type"])

    def test_bulk_alert_ingestion(self):
        """Bulk endpoint should process multiple alerts."""
        response = client.post(
            "/api/alerts/bulk",
            json={
                "source": "generic",
                "alerts": [
                    {"alert_type": "brute_force", "severity": "high", "source_ip": "1.2.3.4"},
                    {"alert_type": "port_scan", "severity": "medium", "source_ip": "5.6.7.8"},
                    {"alert_type": "suspicious_login", "severity": "low", "source_ip": "9.10.11.12"},
                ],
            },
        )
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["total_received"], 3)
        self.assertEqual(data["total_processed"], 3)
        self.assertEqual(len(data["alert_ids"]), 3)

    def test_webhook_response_includes_playbook_data(self):
        """Webhook response should include playbook_name and response_actions."""
        data = self._send_alert({
            "alert_type": "brute_force",
            "severity": "high",
            "source_ip": "185.220.101.45",
            "description": "Brute force login",
        })
        # playbook_name may or may not be present depending on enrichment
        # but the field should exist in the response
        self.assertIn("playbook_name", data)
        self.assertIn("response_actions", data)


# ═════════════════════════════════════════════════════
# Alert Filtering & CRUD Tests
# ═════════════════════════════════════════════════════

class TestAlertCRUD(_IntegrationTestBase):
    """Test alert querying, filtering, and deletion via API."""

    def _seed_alerts(self):
        """Seed the store with multiple alert types."""
        alerts = [
            {"alert_type": "brute_force", "severity": "high", "source_ip": "1.1.1.1"},
            {"alert_type": "malware_detected", "severity": "critical", "source_ip": "2.2.2.2"},
            {"alert_type": "suspicious_login", "severity": "medium", "source_ip": "3.3.3.3"},
            {"alert_type": "port_scan", "severity": "low", "source_ip": "4.4.4.4"},
        ]
        ids = []
        for a in alerts:
            resp = client.post("/api/alerts", json={"source": "generic", "payload": a})
            ids.append(resp.json()["alert_id"])
        return ids

    def test_filter_by_severity(self):
        self._seed_alerts()
        response = client.get("/api/alerts?severity=critical")
        self.assertEqual(response.status_code, 200)
        alerts = response.json()
        self.assertTrue(all(a["severity"] == "critical" for a in alerts))

    def test_filter_by_type(self):
        self._seed_alerts()
        response = client.get("/api/alerts?alert_type=brute_force")
        self.assertEqual(response.status_code, 200)
        alerts = response.json()
        self.assertTrue(all(a["alert_type"] == "brute_force" for a in alerts))

    def test_pagination(self):
        self._seed_alerts()
        response = client.get("/api/alerts?limit=2&offset=0")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()), 2)

    def test_delete_alert(self):
        ids = self._seed_alerts()
        response = client.delete(f"/api/alerts/{ids[0]}")
        self.assertEqual(response.status_code, 200)
        # Verify it's gone
        response = client.get(f"/api/alerts/{ids[0]}")
        self.assertEqual(response.status_code, 404)

    def test_get_nonexistent_alert(self):
        response = client.get("/api/alerts/nonexistent-id")
        self.assertEqual(response.status_code, 404)

    def test_delete_nonexistent_alert(self):
        response = client.delete("/api/alerts/nonexistent-id")
        self.assertEqual(response.status_code, 404)


# ═════════════════════════════════════════════════════
# Playbook & Containment API Integration Tests
# ═════════════════════════════════════════════════════

class TestPlaybookAPI(_IntegrationTestBase):
    """Test playbook and containment API endpoints."""

    def test_list_registered_playbooks(self):
        response = client.get("/api/playbooks")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertIn("brute_force", data["playbooks"])
        self.assertIn("malware_detected", data["playbooks"])
        self.assertIn("suspicious_login", data["playbooks"])
        self.assertIn("port_scan", data["playbooks"])
        self.assertIn("data_exfiltration", data["playbooks"])
        self.assertIn("_default", data["playbooks"])

    def test_playbook_history_empty(self):
        response = client.get("/api/playbooks/history")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["total"], 0)

    def test_pending_approvals_empty(self):
        response = client.get("/api/playbooks/pending")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["total"], 0)

    def test_approve_nonexistent(self):
        response = client.post("/api/playbooks/approve/fake-id")
        self.assertEqual(response.status_code, 404)

    def test_reject_nonexistent(self):
        response = client.post("/api/playbooks/reject/fake-id")
        self.assertEqual(response.status_code, 404)


class TestContainmentAPI(_IntegrationTestBase):
    """Test containment management API endpoints."""

    def test_empty_blocklist(self):
        response = client.get("/api/containment/blocklist")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["blocked_count"], 0)

    def test_manual_block_ip(self):
        response = client.post("/api/containment/block/192.168.1.100")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertFalse(data["already_blocked"])

        # Verify it's in the blocklist
        response = client.get("/api/containment/blocklist")
        data = response.json()
        self.assertEqual(data["blocked_count"], 1)
        self.assertIn("192.168.1.100", data["blocklist"])

    def test_block_ip_already_blocked(self):
        client.post("/api/containment/block/192.168.1.100")
        response = client.post("/api/containment/block/192.168.1.100")
        data = response.json()
        self.assertTrue(data["already_blocked"])

    def test_manual_unblock_ip(self):
        client.post("/api/containment/block/192.168.1.100")
        response = client.post("/api/containment/unblock/192.168.1.100")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["success"])

    def test_unblock_nonexistent(self):
        response = client.post("/api/containment/unblock/1.1.1.1")
        self.assertEqual(response.status_code, 404)

    def test_firewall_log(self):
        client.post("/api/containment/block/1.2.3.4")
        response = client.get("/api/containment/firewall/log")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["total"], 1)

    def test_empty_isolated_instances(self):
        response = client.get("/api/containment/isolated")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["isolated_count"], 0)

    def test_restore_nonexistent_instance(self):
        response = client.post("/api/containment/restore/web-server-01")
        self.assertEqual(response.status_code, 404)

    def test_notification_history(self):
        response = client.get("/api/containment/notifications")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("total_sent", data)

    def test_containment_summary(self):
        response = client.get("/api/containment/summary")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertIn("firewall", data)
        self.assertIn("isolation", data)
        self.assertIn("notifications", data)
        self.assertIn("playbooks", data)


# ═════════════════════════════════════════════════════
# Edge Case & Error Handling Tests
# ═════════════════════════════════════════════════════

class TestEdgeCases(_IntegrationTestBase):
    """Test boundary conditions and error handling."""

    def test_alert_with_empty_payload(self):
        """Empty payload should still normalize (with defaults)."""
        response = client.post(
            "/api/alerts",
            json={"source": "generic", "payload": {}},
        )
        # Should succeed with default values
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertEqual(data["alert_type"], "unknown")
        self.assertEqual(data["severity"], "medium")

    def test_alert_with_unknown_source(self):
        """Unknown SIEM source should fall back to generic normalization."""
        response = client.post(
            "/api/alerts",
            json={
                "source": "unknown_siem",
                "payload": {
                    "alert_type": "brute_force",
                    "severity": "high",
                },
            },
        )
        self.assertEqual(response.status_code, 201)

    def test_alert_with_all_ioc_types(self):
        """Alert with multiple IoC types should extract all of them."""
        response = client.post(
            "/api/alerts",
            json={
                "source": "generic",
                "payload": {
                    "alert_type": "malware_detected",
                    "severity": "critical",
                    "source_ip": "103.24.55.12",
                    "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
                    "url": "http://evil.com/malware.exe",
                    "email": "phisher@evil.com",
                    "description": "Complex multi-IoC alert",
                },
            },
        )
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertGreater(data["ioc_count"], 0)

    def test_enrichment_manual_trigger(self):
        """Manual enrichment should work for stored alerts."""
        # First, create an alert
        resp = client.post(
            "/api/alerts",
            json={
                "source": "generic",
                "payload": {
                    "alert_type": "brute_force",
                    "severity": "high",
                    "source_ip": "185.220.101.45",
                },
            },
        )
        alert_id = resp.json()["alert_id"]

        # Trigger manual enrichment
        response = client.post(f"/api/enrich/{alert_id}")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])

    def test_enrichment_nonexistent_alert(self):
        response = client.post("/api/enrich/nonexistent-id")
        self.assertEqual(response.status_code, 404)

    def test_enrichment_cache_stats(self):
        response = client.get("/api/enrichment/cache")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["success"])

    def test_clear_enrichment_cache(self):
        response = client.delete("/api/enrichment/cache")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["success"])

    def test_invalid_json_body(self):
        """Invalid request body should return 422."""
        response = client.post(
            "/api/alerts",
            content="not valid json",
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(response.status_code, 422)

    def test_missing_payload_field(self):
        """Missing required 'payload' field should return 422."""
        response = client.post(
            "/api/alerts",
            json={"source": "generic"},
        )
        self.assertEqual(response.status_code, 422)

    def test_alert_with_very_long_description(self):
        """Alert with very long description should still process."""
        response = client.post(
            "/api/alerts",
            json={
                "source": "generic",
                "payload": {
                    "alert_type": "brute_force",
                    "severity": "medium",
                    "description": "A" * 10000,
                },
            },
        )
        self.assertEqual(response.status_code, 201)


# ═════════════════════════════════════════════════════
# Full Pipeline Flow Tests
# ═════════════════════════════════════════════════════

class TestFullPipelineFlow(_IntegrationTestBase):
    """Test complete end-to-end flows through the entire system."""

    def test_alert_lifecycle_create_enrich_delete(self):
        """Full lifecycle: create → verify → delete."""
        # Create
        resp = client.post(
            "/api/alerts",
            json={
                "source": "generic",
                "payload": {
                    "alert_type": "port_scan",
                    "severity": "low",
                    "source_ip": "91.198.174.192",
                },
            },
        )
        alert_id = resp.json()["alert_id"]

        # Verify exists
        resp = client.get(f"/api/alerts/{alert_id}")
        self.assertEqual(resp.status_code, 200)

        # Delete
        resp = client.delete(f"/api/alerts/{alert_id}")
        self.assertEqual(resp.status_code, 200)

        # Verify gone
        resp = client.get(f"/api/alerts/{alert_id}")
        self.assertEqual(resp.status_code, 404)

    def test_containment_block_and_unblock_flow(self):
        """Full containment flow: block → verify → unblock → verify."""
        # Block
        client.post("/api/containment/block/10.0.0.1")
        resp = client.get("/api/containment/blocklist")
        self.assertIn("10.0.0.1", resp.json()["blocklist"])

        # Unblock
        client.post("/api/containment/unblock/10.0.0.1")
        resp = client.get("/api/containment/blocklist")
        self.assertNotIn("10.0.0.1", resp.json()["blocklist"])

        # Log should have 2 entries
        resp = client.get("/api/containment/firewall/log")
        self.assertEqual(resp.json()["total"], 2)

    def test_multiple_alerts_stats_accuracy(self):
        """Stats should accurately reflect multiple alerts of different types."""
        types = ["brute_force", "malware_detected", "suspicious_login",
                 "port_scan", "brute_force"]
        for t in types:
            client.post(
                "/api/alerts",
                json={"source": "generic", "payload": {"alert_type": t, "severity": "high"}},
            )

        resp = client.get("/api/stats")
        stats = resp.json()
        self.assertEqual(stats["total_alerts"], 5)
        self.assertEqual(stats["by_type"]["brute_force"], 2)
        self.assertEqual(stats["by_type"]["malware_detected"], 1)


if __name__ == "__main__":
    unittest.main()
