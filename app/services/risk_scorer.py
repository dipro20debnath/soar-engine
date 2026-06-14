"""SOAR Engine - Risk Scoring Algorithm

Calculates an overall risk score (0-100) for each alert based on
multiple weighted factors from the enrichment data.

Scoring Formula:
    risk_score = (
        ip_reputation_score * 0.40 +    # 40% weight - IP abuse reputation
        severity_score      * 0.30 +    # 30% weight - alert severity level
        ioc_score           * 0.15 +    # 15% weight - number of IoCs found
        vt_score            * 0.15      # 15% weight - VirusTotal detections
    )

Risk Levels:
    0-29   → Low risk     (log only)
    30-59  → Medium risk  (notify analyst)
    60-79  → High risk    (auto-block recommended)
    80-100 → Critical     (immediate containment)
"""

import logging
from typing import Optional

from app.models.alert import NormalizedAlert, AlertSeverity
from app.models.enrichment import EnrichmentResult, IPReputation, FileHashResult

logger = logging.getLogger(__name__)


# ── Severity to Numeric Score Mapping ─────────────────
SEVERITY_SCORES = {
    AlertSeverity.INFO: 10,
    AlertSeverity.LOW: 25,
    AlertSeverity.MEDIUM: 50,
    AlertSeverity.HIGH: 75,
    AlertSeverity.CRITICAL: 100,
}

# ── Weight Configuration ──────────────────────────────
WEIGHT_IP_REPUTATION = 0.40
WEIGHT_SEVERITY = 0.30
WEIGHT_IOC_COUNT = 0.15
WEIGHT_VT_DETECTION = 0.15


def calculate_risk_score(
    alert: NormalizedAlert,
    enrichment: Optional[EnrichmentResult] = None,
) -> float:
    """Calculate the overall risk score for an alert.

    Combines multiple threat signals into a single 0-100 score
    that determines what automated response action to take.

    Args:
        alert: The normalized alert with severity and IoC data.
        enrichment: Optional enrichment result with IP and hash lookups.

    Returns:
        A risk score between 0.0 and 100.0 (rounded to 1 decimal).
    """
    # ── Factor 1: IP Reputation (0-100) ──────────────
    ip_score = _calculate_ip_score(enrichment)

    # ── Factor 2: Alert Severity (0-100) ─────────────
    severity_score = SEVERITY_SCORES.get(alert.severity, 50)

    # ── Factor 3: IoC Count (0-100) ──────────────────
    ioc_score = _calculate_ioc_score(len(alert.iocs))

    # ── Factor 4: VirusTotal Detection (0-100) ───────
    vt_score = _calculate_vt_score(enrichment)

    # ── Weighted Combination ─────────────────────────
    raw_score = (
        ip_score * WEIGHT_IP_REPUTATION +
        severity_score * WEIGHT_SEVERITY +
        ioc_score * WEIGHT_IOC_COUNT +
        vt_score * WEIGHT_VT_DETECTION
    )

    # Clamp to 0-100 range
    final_score = round(min(max(raw_score, 0.0), 100.0), 1)

    logger.info(
        f"Risk score for {alert.alert_id}: {final_score} "
        f"(ip={ip_score}, severity={severity_score}, "
        f"ioc={ioc_score}, vt={vt_score})"
    )

    return final_score


def _calculate_ip_score(enrichment: Optional[EnrichmentResult]) -> float:
    """Calculate the IP reputation component of the risk score.

    Uses the highest abuse confidence score among all checked IPs.
    If no IPs were enriched, returns a neutral score of 30.
    """
    if not enrichment or not enrichment.ip_results:
        return 30.0  # Neutral — no data available

    # Use the worst (highest) abuse score found
    max_abuse_score = max(
        r.abuse_confidence_score for r in enrichment.ip_results
    )
    return float(max_abuse_score)


def _calculate_ioc_score(ioc_count: int) -> float:
    """Map IoC count to a 0-100 score.

    More IoCs generally indicate a more complex or serious attack.

    Mapping:
        0 IoCs      → 0   (nothing to work with)
        1-2 IoCs    → 30  (basic indicators)
        3-5 IoCs    → 60  (multiple indicators — suspicious)
        6-10 IoCs   → 80  (many indicators — likely active threat)
        11+ IoCs    → 100 (highly complex attack)
    """
    if ioc_count == 0:
        return 0.0
    elif ioc_count <= 2:
        return 30.0
    elif ioc_count <= 5:
        return 60.0
    elif ioc_count <= 10:
        return 80.0
    else:
        return 100.0


def _calculate_vt_score(enrichment: Optional[EnrichmentResult]) -> float:
    """Calculate the VirusTotal detection component.

    If any hash is flagged as malicious, the score is high.
    Uses the detection ratio to determine the exact score.
    """
    if not enrichment or not enrichment.hash_results:
        return 0.0  # No hashes to check

    max_score = 0.0

    for result in enrichment.hash_results:
        if result.is_malicious:
            # Parse detection ratio like "45/72" to calculate a percentage
            if result.detection_ratio:
                try:
                    parts = result.detection_ratio.split("/")
                    detected = int(parts[0])
                    total = int(parts[1])
                    if total > 0:
                        ratio_score = (detected / total) * 100
                        max_score = max(max_score, ratio_score)
                except (ValueError, IndexError):
                    max_score = max(max_score, 80.0)  # Default for malicious
            else:
                max_score = max(max_score, 80.0)
        else:
            # Not flagged but still checked — minor score
            if result.detection_ratio:
                try:
                    parts = result.detection_ratio.split("/")
                    detected = int(parts[0])
                    if detected > 0:
                        max_score = max(max_score, min(detected * 5.0, 40.0))
                except (ValueError, IndexError):
                    pass

    return min(max_score, 100.0)


def get_risk_level(score: float) -> str:
    """Convert a numeric risk score to a human-readable risk level.

    Args:
        score: Risk score between 0 and 100.

    Returns:
        One of: "low", "medium", "high", "critical"
    """
    if score >= 80:
        return "critical"
    elif score >= 60:
        return "high"
    elif score >= 30:
        return "medium"
    else:
        return "low"


def get_risk_summary(score: float) -> dict:
    """Generate a detailed risk summary for dashboard display.

    Args:
        score: The calculated risk score.

    Returns:
        Dictionary with score, level, color, and recommended action.
    """
    level = get_risk_level(score)

    summaries = {
        "low": {
            "color": "#22c55e",
            "action": "Log and monitor. No immediate action required.",
            "icon": "info",
        },
        "medium": {
            "color": "#f59e0b",
            "action": "Review alert details. Notify analyst if pattern continues.",
            "icon": "warning",
        },
        "high": {
            "color": "#ef4444",
            "action": "Auto-block source IP. Investigate target host.",
            "icon": "alert",
        },
        "critical": {
            "color": "#dc2626",
            "action": "Immediate containment. Block IP, isolate host, notify SOC team.",
            "icon": "critical",
        },
    }

    return {
        "score": score,
        "level": level,
        "description": f"Risk Level: {level.upper()} ({score}/100)",
        **summaries.get(level, summaries["medium"]),
    }
