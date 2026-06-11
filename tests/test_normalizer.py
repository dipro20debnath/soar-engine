"""
Unit Tests - Alert Normalizer Service

Tests the core normalization pipeline including:
- Multi-SIEM format parsing (Splunk, Elastic, Generic)
- Timestamp normalization
- Severity mapping
- IoC extraction (IPs, hashes, URLs, emails)
- Alert type classification
"""

import pytest
from datetime import datetime

from app.services.normalizer import (
    normalize_alert,
    extract_iocs,
    _normalize_timestamp,
    _is_private_ip,
    _classify_alert_type,
)
from app.models.alert import AlertType, AlertSeverity, AlertStatus, SIEMSource


class TestIoCExtraction:
    """Tests for Indicator of Compromise extraction."""

    def test_extract_ipv4(self):
        """Should extract public IPv4 addresses from payload."""
        data = {"source_ip": "103.24.55.12", "message": "Attack from 185.220.101.45"}
        iocs = extract_iocs(data)
        ip_iocs = [ioc for ioc in iocs if ioc.ioc_type == "ip"]
        assert len(ip_iocs) >= 2
        assert any(ioc.value == "103.24.55.12" for ioc in ip_iocs)
        assert any(ioc.value == "185.220.101.45" for ioc in ip_iocs)

    def test_exclude_private_ips(self):
        """Should NOT extract private/reserved IP addresses."""
        data = {"internal": "192.168.1.1", "localhost": "127.0.0.1"}
        iocs = extract_iocs(data)
        ip_iocs = [ioc for ioc in iocs if ioc.ioc_type == "ip"]
        assert len(ip_iocs) == 0

    def test_extract_sha256_hash(self):
        """Should extract SHA-256 file hashes."""
        hash_val = "e99a18c428cb38d5f260853678922e03abd833b3ba0f0b4e2b56b6e5c4b0e7a1"
        data = {"file_hash": hash_val}
        iocs = extract_iocs(data)
        hash_iocs = [ioc for ioc in iocs if "hash" in ioc.ioc_type]
        assert len(hash_iocs) >= 1
        assert any(ioc.value == hash_val for ioc in hash_iocs)

    def test_extract_url(self):
        """Should extract URLs from payload."""
        data = {"c2_server": "http://malware-c2.evil.com/beacon"}
        iocs = extract_iocs(data)
        url_iocs = [ioc for ioc in iocs if ioc.ioc_type == "url"]
        assert len(url_iocs) >= 1

    def test_extract_email(self):
        """Should extract email addresses from payload."""
        data = {"attacker_email": "attacker@evil.com"}
        iocs = extract_iocs(data)
        email_iocs = [ioc for ioc in iocs if ioc.ioc_type == "email"]
        assert len(email_iocs) >= 1

    def test_empty_payload(self):
        """Should return empty list for empty payload."""
        iocs = extract_iocs({})
        assert iocs == []


class TestTimestampNormalization:
    """Tests for timestamp parsing and normalization."""

    def test_iso_format(self):
        """Should parse ISO 8601 timestamps."""
        result = _normalize_timestamp("2026-06-11T10:30:00Z")
        assert isinstance(result, datetime)
        assert result.year == 2026

    def test_unix_epoch(self):
        """Should parse Unix epoch timestamps."""
        result = _normalize_timestamp(1749638400)  # Some future timestamp
        assert isinstance(result, datetime)

    def test_none_returns_now(self):
        """Should return current time for None input."""
        result = _normalize_timestamp(None)
        assert isinstance(result, datetime)

    def test_invalid_string(self):
        """Should return current time for unparseable strings."""
        result = _normalize_timestamp("not_a_timestamp")
        assert isinstance(result, datetime)


class TestPrivateIPDetection:
    """Tests for private IP address detection."""

    def test_class_a_private(self):
        assert _is_private_ip("10.0.1.50") is True

    def test_class_b_private(self):
        assert _is_private_ip("172.16.0.1") is True

    def test_class_c_private(self):
        assert _is_private_ip("192.168.1.1") is True

    def test_localhost(self):
        assert _is_private_ip("127.0.0.1") is True

    def test_public_ip(self):
        assert _is_private_ip("103.24.55.12") is False

    def test_another_public(self):
        assert _is_private_ip("8.8.8.8") is False


class TestAlertTypeClassification:
    """Tests for automatic alert type detection from payload keywords."""

    def test_brute_force_detection(self):
        data = {"message": "Multiple failed login attempts detected"}
        result = _classify_alert_type(data)
        assert result == AlertType.BRUTE_FORCE

    def test_malware_detection(self):
        data = {"message": "Malware Emotet found on server"}
        result = _classify_alert_type(data)
        assert result == AlertType.MALWARE_DETECTED

    def test_suspicious_login(self):
        data = {"message": "Impossible travel detected for user admin"}
        result = _classify_alert_type(data)
        assert result == AlertType.SUSPICIOUS_LOGIN

    def test_port_scan(self):
        data = {"message": "Port scan from external IP"}
        result = _classify_alert_type(data)
        assert result == AlertType.PORT_SCAN

    def test_unknown_type(self):
        data = {"message": "Something happened"}
        result = _classify_alert_type(data)
        assert result == AlertType.UNKNOWN


class TestGenericAlertNormalization:
    """Tests for full normalization pipeline with generic SIEM format."""

    def test_basic_normalization(self):
        """Should normalize a basic generic alert payload."""
        payload = {
            "timestamp": "2026-06-11T10:00:00Z",
            "alert_type": "brute_force",
            "severity": "high",
            "source_ip": "103.24.55.12",
            "target": "web-server-01",
            "description": "Brute force attack detected",
        }
        result = normalize_alert("generic", payload)

        assert result.alert_type == AlertType.BRUTE_FORCE
        assert result.severity == AlertSeverity.HIGH
        assert result.status == AlertStatus.NORMALIZED
        assert result.source_ip == "103.24.55.12"
        assert result.target_host == "web-server-01"
        assert result.alert_id is not None
        assert len(result.alert_id) > 0

    def test_iocs_extracted(self):
        """Should extract IoCs during normalization."""
        payload = {
            "timestamp": "2026-06-11T10:00:00Z",
            "source_ip": "185.220.101.45",
            "description": "Attack from 185.220.101.45",
        }
        result = normalize_alert("generic", payload)
        assert len(result.iocs) >= 1
        assert any(ioc.value == "185.220.101.45" for ioc in result.iocs)

    def test_raw_payload_preserved(self):
        """Should preserve the original raw payload for audit trail."""
        payload = {"timestamp": "2026-06-11T10:00:00Z", "custom_field": "important_data"}
        result = normalize_alert("generic", payload)
        assert result.raw_payload == payload

    def test_default_severity(self):
        """Should default to MEDIUM severity if not specified."""
        payload = {"timestamp": "2026-06-11T10:00:00Z"}
        result = normalize_alert("generic", payload)
        assert result.severity == AlertSeverity.MEDIUM


class TestSplunkAlertNormalization:
    """Tests for Splunk SIEM format normalization."""

    def test_splunk_format(self):
        """Should parse Splunk-style alert payloads."""
        payload = {
            "result": {
                "_time": "2026-06-11T10:00:00Z",
                "src_ip": "103.24.55.12",
                "dest": "web-server-01",
                "_raw": "Failed password for admin from 103.24.55.12",
            },
            "severity": "critical",
            "alert_type": "brute_force",
        }
        result = normalize_alert("splunk", payload)

        assert result.siem_source == SIEMSource.SPLUNK
        assert result.severity == AlertSeverity.CRITICAL
        assert result.alert_type == AlertType.BRUTE_FORCE


class TestElasticAlertNormalization:
    """Tests for Elastic SIEM format normalization."""

    def test_elastic_format(self):
        """Should parse Elastic-style alert payloads."""
        payload = {
            "@timestamp": "2026-06-11T10:00:00Z",
            "_source": {
                "source.ip": "185.220.101.45",
                "host.name": "api-server-02",
            },
            "severity": 4,
            "alert_type": "suspicious_login",
            "message": "Suspicious login detected",
        }
        result = normalize_alert("elastic", payload)

        assert result.siem_source == SIEMSource.ELASTIC
        assert result.severity == AlertSeverity.HIGH  # 4 = HIGH
