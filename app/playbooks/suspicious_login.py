"""SOAR Engine - Suspicious Login Response Playbook

Automated response for suspicious login events (unusual geo-location,
impossible travel, or after-hours access).

Risk Tiers:
    - Low risk  (< 40):  Log only
    - Medium    (40-70):  Force password reset, notify user
    - High risk (> 70):   Lock account, block IP, notify SOC

Enrichment Boosters:
    - If source IP is a known Tor exit node -> escalate one tier
    - If source IP has AbuseIPDB score >= 85 -> escalate one tier
    - If source IP country differs from usual -> add geo_anomaly tag
"""

import logging
from typing import Optional

from app.models.alert import NormalizedAlert
from app.models.enrichment import EnrichmentResult
from app.playbooks.base import BasePlaybook

logger = logging.getLogger(__name__)

# Countries that are commonly flagged in suspicious login scenarios
SUSPICIOUS_COUNTRIES = {"RU", "CN", "KP", "IR", "RO", "UA", "NG"}


class SuspiciousLoginPlaybook(BasePlaybook):
    """Response playbook for suspicious login attempts.

    Evaluates risk score, source IP reputation, and geo-location data
    to determine whether the login should be allowed, the user warned,
    or the account locked.
    """

    @property
    def name(self) -> str:
        return "suspicious_login_response"

    @property
    def description(self) -> str:
        return "Respond to suspicious logins with account protection actions"

    def execute(
        self,
        alert: NormalizedAlert,
        enrichment: Optional[EnrichmentResult] = None,
    ) -> list[str]:
        """Execute suspicious login response based on risk score and enrichment.

        Args:
            alert: The normalized alert (type should be SUSPICIOUS_LOGIN).
            enrichment: Optional enrichment data with IP reputation.

        Returns:
            List of actions taken.
        """
        risk = self._get_risk_score(alert)
        source_ip = alert.source_ip or "unknown"
        actions = []

        # ── Extract enrichment intelligence ───────────────
        abuse_score = 0
        country = "unknown"
        is_tor = False
        isp = "unknown"

        if enrichment and enrichment.ip_results:
            for ip_result in enrichment.ip_results:
                if ip_result.ip_address == source_ip:
                    abuse_score = ip_result.abuse_confidence_score
                    country = ip_result.country_code or "unknown"
                    is_tor = ip_result.is_tor
                    isp = ip_result.isp or "unknown"
                    break
            else:
                worst = max(enrichment.ip_results, key=lambda r: r.abuse_confidence_score)
                abuse_score = worst.abuse_confidence_score
                country = worst.country_code or "unknown"
                is_tor = worst.is_tor
                isp = worst.isp or "unknown"

        # ── Enrichment-based escalation ───────────────────
        effective_risk = risk

        # Tor exit node -> always escalate to at least medium
        if is_tor and effective_risk < 40:
            effective_risk = max(risk, 40.0)
            actions.append("enrichment_escalation:tor_exit_node")
            logger.info(
                f"[SuspiciousLoginPlaybook] Escalating: "
                f"login from Tor exit node {source_ip}"
            )

        # Very high abuse score -> escalate to high risk
        if abuse_score >= 85 and effective_risk <= 70:
            effective_risk = max(risk, 71.0)
            actions.append(f"enrichment_escalation:abuse_score={abuse_score}")
            logger.info(
                f"[SuspiciousLoginPlaybook] Escalating: "
                f"high abuse score ({abuse_score}/100) for {source_ip}"
            )

        # ── Tiered Response ───────────────────────────────
        if effective_risk > 70:
            # ── High Risk: Lock Account + Block IP ────────
            actions.append("lock_account")
            actions.append(f"block_ip:{source_ip}")
            actions.append("force_password_reset")
            actions.append("notify_soc:critical")
            logger.warning(
                f"[SuspiciousLoginPlaybook] HIGH RISK ({risk:.1f}): "
                f"Locking account and blocking IP {source_ip}"
            )

        elif effective_risk >= 40:
            # ── Medium Risk: Password Reset + Notify ──────
            actions.append("force_password_reset")
            actions.append("notify_user")
            logger.info(
                f"[SuspiciousLoginPlaybook] MEDIUM RISK ({risk:.1f}): "
                f"Forcing password reset for login from {source_ip}"
            )

        else:
            # ── Low Risk: Log Only ────────────────────────
            actions.append("log_only")
            logger.info(
                f"[SuspiciousLoginPlaybook] LOW RISK ({risk:.1f}): "
                f"Logging suspicious login from {source_ip}"
            )

        # ── Enrichment-based tags ─────────────────────────
        if is_tor:
            actions.append(f"tag:tor_exit_node:{source_ip}")

        if country in SUSPICIOUS_COUNTRIES:
            actions.append(f"tag:suspicious_country:{country}")

        if country != "unknown":
            actions.append(f"tag:login_country:{country}")

        return actions
