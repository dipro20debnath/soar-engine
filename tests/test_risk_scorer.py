"""
Unit Tests - Risk Scoring Algorithm

Tests the weighted risk scoring system including:
- Individual factor calculations (IP, severity, IoC count, VT)
- Combined weighted scoring
- Risk level classification
- Edge cases (no enrichment, missing data)
- Risk summary generation
"""

import pytest
from datetime import datetime

from app.services.risk_scorer import (
    calculate_risk_score,
    get_risk_level,
    get_risk_summary,
    _calculate_ip_score,
    _calculate_ioc_score,
    _calculate_vt_score,
)
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


def _make_alert(severity=AlertSeverity.MEDIUM, ioc_count=1) -> NormalizedAlert:
    """Helper to create a test alert."""
    iocs = [IoC(ioc_type="ip", value=f"1.2.3.{i}") for i in range(ioc_count)]
    return NormalizedAlert(
        timestamp=datetime(2026, 6, 14, 10, 0, 0),
        alert_type=AlertType.BRUTE_FORCE,
        severity=severity,
        status=AlertStatus.NORMALIZED,
        source_ip="103.24.55.12",
        description="Test alert for risk scoring",
        iocs=iocs,
    )


def _make_enrichment(
    alert_id: str = "test",
    ip_score: int = 50,
    is_malicious: bool = False,
    detection_ratio: str = "0/72",
) -> EnrichmentResult:
    """Helper to create a test enrichment result."""
    return EnrichmentResult(
        alert_id=alert_id,
        ip_results=[
            IPReputation(
                ip_address="103.24.55.12",
                abuse_confidence_score=ip_score,
                country_code="RU",
                isp="Hetzner",
            )
        ],
        hash_results=[
            FileHashResult(
                file_hash="a" * 64,
                hash_type="sha256",
                detection_ratio=detection_ratio,
                is_malicious=is_malicious,
                malware_family="Emotet" if is_malicious else None,
            )
        ] if detection_ratio else [],
    )


# ── Individual Factor Tests ──────────────────────────

class TestIPScoreCalculation:
    """Tests for the IP reputation score component."""

    def test_no_enrichment_returns_neutral(self):
        """No enrichment data should return neutral score of 30."""
        score = _calculate_ip_score(None)
        assert score == 30.0

    def test_no_ip_results_returns_neutral(self):
        """Enrichment with no IP results should return neutral score."""
        enrichment = EnrichmentResult(alert_id="test")
        score = _calculate_ip_score(enrichment)
        assert score == 30.0

    def test_high_abuse_score(self):
        """High abuse IP should return high score."""
        enrichment = _make_enrichment(ip_score=95)
        score = _calculate_ip_score(enrichment)
        assert score == 95.0

    def test_low_abuse_score(self):
        """Low abuse IP should return low score."""
        enrichment = _make_enrichment(ip_score=5)
        score = _calculate_ip_score(enrichment)
        assert score == 5.0

    def test_uses_worst_ip(self):
        """Should use the highest abuse score among multiple IPs."""
        enrichment = EnrichmentResult(
            alert_id="test",
            ip_results=[
                IPReputation(ip_address="1.2.3.4", abuse_confidence_score=10),
                IPReputation(ip_address="5.6.7.8", abuse_confidence_score=90),
                IPReputation(ip_address="9.10.11.12", abuse_confidence_score=45),
            ],
        )
        score = _calculate_ip_score(enrichment)
        assert score == 90.0


class TestIoCScoreCalculation:
    """Tests for the IoC count score component."""

    def test_zero_iocs(self):
        assert _calculate_ioc_score(0) == 0.0

    def test_one_ioc(self):
        assert _calculate_ioc_score(1) == 30.0

    def test_two_iocs(self):
        assert _calculate_ioc_score(2) == 30.0

    def test_three_iocs(self):
        assert _calculate_ioc_score(3) == 60.0

    def test_five_iocs(self):
        assert _calculate_ioc_score(5) == 60.0

    def test_six_iocs(self):
        assert _calculate_ioc_score(6) == 80.0

    def test_eleven_iocs(self):
        assert _calculate_ioc_score(11) == 100.0


class TestVTScoreCalculation:
    """Tests for the VirusTotal detection score component."""

    def test_no_enrichment(self):
        score = _calculate_vt_score(None)
        assert score == 0.0

    def test_no_hash_results(self):
        enrichment = EnrichmentResult(alert_id="test")
        score = _calculate_vt_score(enrichment)
        assert score == 0.0

    def test_malicious_detection(self):
        """Malicious hash with high detection ratio should give high score."""
        enrichment = _make_enrichment(is_malicious=True, detection_ratio="45/72")
        score = _calculate_vt_score(enrichment)
        assert score > 50.0

    def test_clean_detection(self):
        """Clean hash should give low or zero score."""
        enrichment = _make_enrichment(is_malicious=False, detection_ratio="0/72")
        score = _calculate_vt_score(enrichment)
        assert score == 0.0

    def test_partial_detection(self):
        """Few detections on a non-malicious hash should give moderate score."""
        enrichment = _make_enrichment(is_malicious=False, detection_ratio="3/72")
        score = _calculate_vt_score(enrichment)
        assert 0 < score <= 40.0


# ── Combined Risk Score Tests ────────────────────────

class TestCalculateRiskScore:
    """Tests for the combined weighted risk score."""

    def test_critical_risk_alert(self):
        """Alert with high abuse IP + critical severity + malware → high score."""
        alert = _make_alert(severity=AlertSeverity.CRITICAL, ioc_count=5)
        enrichment = _make_enrichment(
            alert_id=alert.alert_id,
            ip_score=95,
            is_malicious=True,
            detection_ratio="50/72",
        )
        score = calculate_risk_score(alert, enrichment)
        assert score >= 75.0, f"Expected critical risk >= 75, got {score}"

    def test_low_risk_alert(self):
        """Alert with clean IP + info severity + no malware → low score."""
        alert = _make_alert(severity=AlertSeverity.INFO, ioc_count=1)
        enrichment = _make_enrichment(
            alert_id=alert.alert_id,
            ip_score=5,
            is_malicious=False,
            detection_ratio="0/72",
        )
        score = calculate_risk_score(alert, enrichment)
        assert score < 30.0, f"Expected low risk < 30, got {score}"

    def test_medium_risk_alert(self):
        """Alert with moderate signals → medium range score."""
        alert = _make_alert(severity=AlertSeverity.MEDIUM, ioc_count=3)
        enrichment = _make_enrichment(
            alert_id=alert.alert_id,
            ip_score=50,
            is_malicious=False,
            detection_ratio="0/72",
        )
        score = calculate_risk_score(alert, enrichment)
        assert 25.0 <= score <= 65.0, f"Expected medium risk 25-65, got {score}"

    def test_no_enrichment(self):
        """Alert without enrichment should still get a score (based on severity + IoCs)."""
        alert = _make_alert(severity=AlertSeverity.HIGH, ioc_count=2)
        score = calculate_risk_score(alert, None)
        assert score > 0, "Score should be positive even without enrichment"

    def test_score_clamped_to_100(self):
        """Score should never exceed 100."""
        alert = _make_alert(severity=AlertSeverity.CRITICAL, ioc_count=20)
        enrichment = _make_enrichment(
            alert_id=alert.alert_id,
            ip_score=100,
            is_malicious=True,
            detection_ratio="72/72",
        )
        score = calculate_risk_score(alert, enrichment)
        assert score <= 100.0

    def test_score_minimum_is_zero(self):
        """Score should never go below 0."""
        alert = _make_alert(severity=AlertSeverity.INFO, ioc_count=0)
        enrichment = _make_enrichment(
            alert_id=alert.alert_id,
            ip_score=0,
            is_malicious=False,
            detection_ratio="0/72",
        )
        score = calculate_risk_score(alert, enrichment)
        assert score >= 0.0


# ── Risk Level Tests ─────────────────────────────────

class TestGetRiskLevel:
    """Tests for risk level classification."""

    def test_critical(self):
        assert get_risk_level(85.0) == "critical"
        assert get_risk_level(100.0) == "critical"

    def test_high(self):
        assert get_risk_level(60.0) == "high"
        assert get_risk_level(79.9) == "high"

    def test_medium(self):
        assert get_risk_level(30.0) == "medium"
        assert get_risk_level(59.9) == "medium"

    def test_low(self):
        assert get_risk_level(0.0) == "low"
        assert get_risk_level(29.9) == "low"


# ── Risk Summary Tests ───────────────────────────────

class TestGetRiskSummary:
    """Tests for risk summary generation."""

    def test_summary_has_required_fields(self):
        summary = get_risk_summary(75.0)
        assert "score" in summary
        assert "level" in summary
        assert "color" in summary
        assert "action" in summary
        assert "description" in summary

    def test_critical_summary(self):
        summary = get_risk_summary(90.0)
        assert summary["level"] == "critical"
        assert "containment" in summary["action"].lower()

    def test_low_summary(self):
        summary = get_risk_summary(10.0)
        assert summary["level"] == "low"
        assert "monitor" in summary["action"].lower()
