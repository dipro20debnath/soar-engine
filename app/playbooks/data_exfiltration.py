"""SOAR Engine - Data Exfiltration Response Playbook

Automated response for data exfiltration (data theft) events.
Data exfiltration is one of the most dangerous alert types because
it means an attacker is actively stealing data.

Risk Tiers:
    - Low risk  (< 40):  Log and monitor traffic patterns
    - Medium    (40-70):  Throttle outbound traffic, notify SOC, create ticket
    - High risk (> 70):   Isolate host, block destination IP, alert SOC critical

Enrichment Boosters:
    - If destination IP has high AbuseIPDB score -> escalate one tier
    - If any C2 URLs found -> always escalate to high-risk
"""

import logging
from typing import Optional

from app.models.alert import NormalizedAlert
from app.models.enrichment import EnrichmentResult
from app.playbooks.base import BasePlaybook

logger = logging.getLogger(__name__)


class DataExfiltrationPlaybook(BasePlaybook):
    """Response playbook for data exfiltration alerts.

    Data exfiltration represents active data theft and is treated
    with urgency. Uses network IoCs and IP reputation to determine
    containment actions.
    """

    @property
    def name(self) -> str:
        return "data_exfiltration_response"

    @property
    def description(self) -> str:
        return "Respond to data exfiltration with traffic blocking and host isolation"

    def execute(
        self,
        alert: NormalizedAlert,
        enrichment: Optional[EnrichmentResult] = None,
    ) -> list[str]:
        """Execute data exfiltration response based on risk score and enrichment.

        Args:
            alert: The normalized alert (type should be DATA_EXFILTRATION).
            enrichment: Optional enrichment data with IP reputation.

        Returns:
            List of actions taken.
        """
        risk = self._get_risk_score(alert)
        source_ip = alert.source_ip or "unknown"
        dest_ip = alert.dest_ip or "unknown"
        target_host = alert.target_host or "unknown-host"
        actions = []

        # ── Extract enrichment intelligence ───────────────
        dest_abuse_score = 0

        if enrichment and enrichment.ip_results:
            # Look for the destination IP in enrichment results
            for ip_result in enrichment.ip_results:
                if ip_result.ip_address == dest_ip:
                    dest_abuse_score = ip_result.abuse_confidence_score
                    break

        # Check for C2 URLs in IoCs
        c2_urls = [ioc.value for ioc in alert.iocs if ioc.ioc_type == "url"]

        # ── Enrichment-based escalation ───────────────────
        effective_risk = risk

        # C2 URLs found -> always high risk
        if c2_urls and effective_risk <= 70:
            effective_risk = max(risk, 71.0)
            actions.append("enrichment_escalation:c2_urls_detected")

        # Destination IP is known malicious -> escalate
        if dest_abuse_score >= 75 and effective_risk <= 70:
            effective_risk = max(risk, 71.0)
            actions.append(f"enrichment_escalation:dest_abuse_score={dest_abuse_score}")

        # ── Tiered Response ───────────────────────────────
        if effective_risk > 70:
            # ── High Risk: Isolate + Block ────────────────
            actions.append(f"isolate_host:{target_host}")

            if dest_ip != "unknown":
                actions.append(f"block_ip:{dest_ip}")

            for url in c2_urls:
                actions.append(f"block_c2_url:{url}")

            actions.append("create_incident_ticket")
            actions.append("notify_soc:critical")
            logger.warning(
                f"[DataExfilPlaybook] HIGH RISK ({risk:.1f}): "
                f"Isolating {target_host}, blocking {dest_ip}"
            )

        elif effective_risk >= 40:
            # ── Medium Risk: Throttle + Monitor ───────────
            actions.append(f"throttle_outbound:{target_host}")

            if dest_ip != "unknown":
                actions.append(f"add_to_watchlist:{dest_ip}")

            actions.append("create_incident_ticket")
            actions.append("notify_soc:warning")
            logger.info(
                f"[DataExfilPlaybook] MEDIUM RISK ({risk:.1f}): "
                f"Throttling outbound traffic from {target_host}"
            )

        else:
            # ── Low Risk: Monitor ─────────────────────────
            actions.append("log_and_monitor")
            actions.append(f"monitor_traffic:{target_host}")
            logger.info(
                f"[DataExfilPlaybook] LOW RISK ({risk:.1f}): "
                f"Monitoring traffic from {target_host}"
            )

        # ── Enrichment-based tags ─────────────────────────
        if c2_urls:
            actions.append(f"tag:c2_communication:{len(c2_urls)}_urls")

        return actions
