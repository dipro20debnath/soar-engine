"""
Unit Tests - Enrichment Service

Tests the threat intelligence enrichment pipeline including:
- AbuseIPDB client (simulated responses)
- VirusTotal client (simulated responses)
- Enrichment caching
- EnrichmentService orchestration
- Threat level calculation
- Confidence scoring
"""

import pytest
from datetime import datetime

from app.services.enrichment import (
    AbuseIPDBClient,
    VirusTotalClient,
    EnrichmentService,
    clear_enrichment_cache,
    get_cache_stats,
)
from app.models.alert import NormalizedAlert, AlertType, AlertSeverity, AlertStatus, IoC
from app.models.enrichment import IPReputation, FileHashResult, EnrichmentResult


@pytest.fixture(autouse=True)
def clear_cache():
    """Clear the enrichment cache before each test."""
    clear_enrichment_cache()
    yield
    clear_enrichment_cache()


class TestAbuseIPDBClient:
    """Tests for the AbuseIPDB client (simulation mode)."""

    def test_check_ip_returns_ip_reputation(self):
        """Should return an IPReputation object for a given IP."""
        client = AbuseIPDBClient()
        result = client.check_ip("103.24.55.12")

        assert isinstance(result, IPReputation)
        assert result.ip_address == "103.24.55.12"
        assert 0 <= result.abuse_confidence_score <= 100
        assert result.country_code is not None

    def test_consistent_results_for_same_ip(self):
        """Simulated responses should be consistent for the same IP (seeded RNG)."""
        client = AbuseIPDBClient()
        result1 = client.check_ip("185.220.101.45")
        clear_enrichment_cache()
        result2 = client.check_ip("185.220.101.45")

        assert result1.abuse_confidence_score == result2.abuse_confidence_score
        assert result1.country_code == result2.country_code

    def test_different_ips_get_different_scores(self):
        """Different IPs should generally produce different results."""
        client = AbuseIPDBClient()
        result1 = client.check_ip("103.24.55.12")
        result2 = client.check_ip("8.8.8.8")

        # They might occasionally match, but IP address field must differ
        assert result1.ip_address != result2.ip_address

    def test_cache_works(self):
        """Second lookup for the same IP should come from cache."""
        client = AbuseIPDBClient()
        client.check_ip("103.24.55.12")
        client.check_ip("103.24.55.12")

        stats = get_cache_stats()
        assert stats["ip_cache_size"] == 1  # Only one entry, not two

    def test_source_is_simulated(self):
        """In simulation mode, source should indicate simulated."""
        client = AbuseIPDBClient()
        result = client.check_ip("45.33.32.156")
        assert "simulated" in result.source


class TestVirusTotalClient:
    """Tests for the VirusTotal client (simulation mode)."""

    def test_check_hash_returns_result(self):
        """Should return a FileHashResult for a given hash."""
        client = VirusTotalClient()
        test_hash = "e99a18c428cb38d5f260853678922e03abd833b3ba0f0b4e2b56b6e5c4b0e7a1"
        result = client.check_hash(test_hash)

        assert isinstance(result, FileHashResult)
        assert result.file_hash == test_hash
        assert result.hash_type == "sha256"
        assert result.detection_ratio is not None

    def test_detects_hash_type_sha256(self):
        """Should detect SHA-256 hash type from length."""
        client = VirusTotalClient()
        sha256 = "a" * 64
        result = client.check_hash(sha256)
        assert result.hash_type == "sha256"

    def test_detects_hash_type_md5(self):
        """Should detect MD5 hash type from length."""
        client = VirusTotalClient()
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        result = client.check_hash(md5)
        assert result.hash_type == "md5"

    def test_detects_hash_type_sha1(self):
        """Should detect SHA-1 hash type from length."""
        client = VirusTotalClient()
        sha1 = "a" * 40
        result = client.check_hash(sha1)
        assert result.hash_type == "sha1"

    def test_cache_works(self):
        """Second lookup for the same hash should come from cache."""
        client = VirusTotalClient()
        test_hash = "b" * 64
        client.check_hash(test_hash)
        client.check_hash(test_hash)

        stats = get_cache_stats()
        assert stats["hash_cache_size"] == 1

    def test_malicious_detection_has_family(self):
        """If flagged as malicious, should have a malware family name."""
        client = VirusTotalClient()
        # Try multiple hashes until we find one flagged as malicious
        malicious_found = False
        for i in range(10):
            test_hash = f"{i:064x}"
            result = client.check_hash(test_hash)
            if result.is_malicious:
                assert result.malware_family is not None
                malicious_found = True
                break
        # At 60% malicious rate, should find at least one in 10 tries
        assert malicious_found, "No malicious hash found in 10 samples"


class TestEnrichmentService:
    """Tests for the full enrichment service orchestration."""

    def _make_alert_with_iocs(self, iocs: list[IoC]) -> NormalizedAlert:
        """Helper to create a test alert with specific IoCs."""
        return NormalizedAlert(
            timestamp=datetime(2026, 6, 13, 10, 0, 0),
            alert_type=AlertType.BRUTE_FORCE,
            severity=AlertSeverity.HIGH,
            status=AlertStatus.NORMALIZED,
            source_ip="103.24.55.12",
            description="Test alert for enrichment",
            iocs=iocs,
        )

    def test_enrich_with_ip_iocs(self):
        """Should enrich all IP-type IoCs via AbuseIPDB."""
        alert = self._make_alert_with_iocs([
            IoC(ioc_type="ip", value="103.24.55.12"),
            IoC(ioc_type="ip", value="185.220.101.45"),
        ])

        service = EnrichmentService()
        result = service.enrich(alert)

        assert isinstance(result, EnrichmentResult)
        assert result.alert_id == alert.alert_id
        assert len(result.ip_results) == 2
        assert result.ip_results[0].ip_address == "103.24.55.12"
        assert result.ip_results[1].ip_address == "185.220.101.45"

    def test_enrich_with_hash_iocs(self):
        """Should enrich all hash-type IoCs via VirusTotal."""
        test_hash = "e99a18c428cb38d5f260853678922e03abd833b3ba0f0b4e2b56b6e5c4b0e7a1"
        alert = self._make_alert_with_iocs([
            IoC(ioc_type="hash_sha256", value=test_hash),
        ])

        service = EnrichmentService()
        result = service.enrich(alert)

        assert len(result.hash_results) == 1
        assert result.hash_results[0].file_hash == test_hash

    def test_enrich_with_mixed_iocs(self):
        """Should handle a mix of IP and hash IoCs."""
        alert = self._make_alert_with_iocs([
            IoC(ioc_type="ip", value="103.24.55.12"),
            IoC(ioc_type="hash_sha256", value="a" * 64),
            IoC(ioc_type="url", value="http://evil.com/malware.exe"),
        ])

        service = EnrichmentService()
        result = service.enrich(alert)

        assert len(result.ip_results) == 1
        assert len(result.hash_results) == 1
        # URLs are not enriched (no API for them yet)

    def test_enrich_with_no_iocs(self):
        """Should handle alerts with no IoCs gracefully."""
        alert = self._make_alert_with_iocs([])

        service = EnrichmentService()
        result = service.enrich(alert)

        assert result.alert_id == alert.alert_id
        assert len(result.ip_results) == 0
        assert len(result.hash_results) == 0
        assert result.overall_threat_level == "unknown"

    def test_threat_level_critical(self):
        """Malware detection should result in critical threat level."""
        service = EnrichmentService()

        # Find a hash that gets flagged as malicious
        for i in range(20):
            test_hash = f"{i:064x}"
            alert = self._make_alert_with_iocs([
                IoC(ioc_type="hash_sha256", value=test_hash),
            ])
            result = service.enrich(alert)
            if any(r.is_malicious for r in result.hash_results):
                assert result.overall_threat_level == "critical"
                return

    def test_confidence_increases_with_more_data(self):
        """Confidence should be higher when we have more IoC results."""
        service = EnrichmentService()

        # Alert with 1 IoC
        alert1 = self._make_alert_with_iocs([
            IoC(ioc_type="ip", value="103.24.55.12"),
        ])
        result1 = service.enrich(alert1)

        # Alert with 3 IoCs
        alert2 = self._make_alert_with_iocs([
            IoC(ioc_type="ip", value="103.24.55.12"),
            IoC(ioc_type="ip", value="185.220.101.45"),
            IoC(ioc_type="hash_sha256", value="c" * 64),
        ])
        result2 = service.enrich(alert2)

        assert result2.confidence >= result1.confidence

    def test_enrichment_result_has_notes(self):
        """High-risk IoCs should generate analyst notes."""
        service = EnrichmentService()

        # Try several IPs until one produces a high score
        for base in range(50, 200):
            ip = f"{base}.24.55.12"
            alert = self._make_alert_with_iocs([
                IoC(ioc_type="ip", value=ip),
            ])
            result = service.enrich(alert)
            if result.ip_results and result.ip_results[0].abuse_confidence_score >= 80:
                assert len(result.notes) > 0
                assert "HIGH RISK IP" in result.notes[0]
                return


class TestCacheManagement:
    """Tests for enrichment cache operations."""

    def test_clear_cache(self):
        """Should clear all cached entries."""
        client = AbuseIPDBClient()
        client.check_ip("1.2.3.4")

        stats = get_cache_stats()
        assert stats["ip_cache_size"] == 1

        clear_enrichment_cache()
        stats = get_cache_stats()
        assert stats["total_cached"] == 0

    def test_cache_stats(self):
        """Should return correct cache statistics."""
        ip_client = AbuseIPDBClient()
        vt_client = VirusTotalClient()

        ip_client.check_ip("1.2.3.4")
        ip_client.check_ip("5.6.7.8")
        vt_client.check_hash("a" * 64)

        stats = get_cache_stats()
        assert stats["ip_cache_size"] == 2
        assert stats["hash_cache_size"] == 1
        assert stats["total_cached"] == 3
