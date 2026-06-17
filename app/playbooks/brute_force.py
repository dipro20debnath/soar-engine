"""SOAR Engine - Brute Force Response Playbook

Automated response for brute-force login attacks.
Uses both risk score AND enrichment data to make intelligent decisions.

Risk Tiers:
    - Low risk  (< 30):  Log only, no action
    - Medium    (30-75):  Watch-list the IP, notify SOC
    - High risk (> 75):   Block IP in firewall, send critical alert

Enrichment Boosters (applied on top of risk tiers):
    - If source IP has AbuseIPDB score >= 90  -> escalate one tier
    - If source IP is a known Tor exit node   -> add tor_flag tag
    - If IP has > 100 abuse reports           -> add repeat_offender tag
"""

import logging
from typing import Optional

from app.models.alert import NormalizedAlert
from app.models.enrichment import EnrichmentResult
from app.playbooks.base import BasePlaybook

logger = logging.getLogger(__name__)

# Countries frequently associated with brute-force attacks (for tagging, not blocking)
HIGH_RISK_COUNTRIES = {"RU", "CN", "KP", "IR"}


class BruteForcePlaybook(BasePlaybook):
    """Response playbook for brute-force login attempts.

    Evaluates the risk score, source IP reputation, and enrichment data
    to decide on proportional containment actions. Uses AbuseIPDB data
    to boost or de-escalate the response.
    """

    @property
    def name(self) -> str:
        return "brute_force_response"

    @property
    def description(self) -> str:
        return "Respond to brute-force login attacks with tiered containment"

    def execute(
        self,
        alert: NormalizedAlert,
        enrichment: Optional[EnrichmentResult] = None,
    ) -> list[str]:
        """Execute brute-force response based on risk score and enrichment.

        Args:
            alert: The normalized alert (type should be BRUTE_FORCE).
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
        total_reports = 0

        if enrichment and enrichment.ip_results:
            # Use the result for the source IP, or the worst IP
            for ip_result in enrichment.ip_results:
                if ip_result.ip_address == source_ip:
                    abuse_score = ip_result.abuse_confidence_score
                    country = ip_result.country_code or "unknown"
                    is_tor = ip_result.is_tor
                    total_reports = ip_result.total_reports
                    break
            else:
                # Fallback: use the worst abuse score from all results
                worst = max(enrichment.ip_results, key=lambda r: r.abuse_confidence_score)
                abuse_score = worst.abuse_confidence_score
                country = worst.country_code or "unknown"
                is_tor = worst.is_tor
                total_reports = worst.total_reports

        # ── Enrichment-based escalation ───────────────────
        # If AbuseIPDB score is extremely high, escalate even medium-risk alerts
        effective_risk = risk
        if abuse_score >= 90 and risk <= 75:
            effective_risk = max(risk, 76.0)  # Force into high-risk tier
            actions.append(f"enrichment_escalation:abuse_score={abuse_score}")
            logger.info(
                f"[BruteForcePlaybook] Escalating due to high abuse score "
                f"({abuse_score}/100) for {source_ip}"
            )

        # ── Tiered Response ───────────────────────────────
        if effective_risk > 75:
            # ── High Risk: Block + Alert ──────────────────
            actions.append(f"block_ip:{source_ip}")
            actions.append("notify_soc:critical")
            logger.warning(
                f"[BruteForcePlaybook] HIGH RISK ({risk:.1f}): "
                f"Blocking IP {source_ip} and sending critical alert"
            )

        elif effective_risk >= 30:
            # ── Medium Risk: Watch + Notify ───────────────
            actions.append(f"add_to_watchlist:{source_ip}")
            actions.append("notify_soc:warning")
            logger.info(
                f"[BruteForcePlaybook] MEDIUM RISK ({risk:.1f}): "
                f"Added {source_ip} to watch list"
            )

        else:
            # ── Low Risk: Log Only ────────────────────────
            actions.append("log_only")
            logger.info(
                f"[BruteForcePlaybook] LOW RISK ({risk:.1f}): "
                f"Logging alert for {source_ip}, no action needed"
            )

        # ── Enrichment-based tags ─────────────────────────
        if is_tor:
            actions.append(f"tag:tor_exit_node:{source_ip}")
            logger.info(f"[BruteForcePlaybook] Source IP {source_ip} is a Tor exit node")

        if total_reports > 100:
            actions.append(f"tag:repeat_offender:{source_ip}")

        if country in HIGH_RISK_COUNTRIES:
            actions.append(f"tag:high_risk_country:{country}")

        return actions
