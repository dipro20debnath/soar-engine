"""SOAR Engine - Port Scan Response Playbook

Automated response for port scanning / network reconnaissance events.

Risk Tiers:
    - Low risk  (< 40):  Log only (likely internal scan or benign)
    - Medium    (40-70):  Rate-limit source IP, notify SOC
    - High risk (> 70):   Block IP in firewall, create incident ticket

Port scans are often a precursor to a larger attack, so even medium-risk
scans should be monitored closely.
"""

import logging
from typing import Optional

from app.models.alert import NormalizedAlert
from app.models.enrichment import EnrichmentResult
from app.playbooks.base import BasePlaybook

logger = logging.getLogger(__name__)


class PortScanPlaybook(BasePlaybook):
    """Response playbook for port scan / network reconnaissance alerts.

    Port scans are typically the first stage of an attack. This playbook
    uses IP reputation data to determine if the scanner is a known
    threat actor or a benign source.
    """

    @property
    def name(self) -> str:
        return "port_scan_response"

    @property
    def description(self) -> str:
        return "Respond to port scanning with rate-limiting and IP blocking"

    def execute(
        self,
        alert: NormalizedAlert,
        enrichment: Optional[EnrichmentResult] = None,
    ) -> list[str]:
        """Execute port scan response based on risk score and enrichment.

        Args:
            alert: The normalized alert (type should be PORT_SCAN).
            enrichment: Optional enrichment data with IP reputation.

        Returns:
            List of actions taken.
        """
        risk = self._get_risk_score(alert)
        source_ip = alert.source_ip or "unknown"
        actions = []

        # ── Extract enrichment intelligence ───────────────
        abuse_score = 0
        total_reports = 0

        if enrichment and enrichment.ip_results:
            for ip_result in enrichment.ip_results:
                if ip_result.ip_address == source_ip:
                    abuse_score = ip_result.abuse_confidence_score
                    total_reports = ip_result.total_reports
                    break
            else:
                worst = max(enrichment.ip_results, key=lambda r: r.abuse_confidence_score)
                abuse_score = worst.abuse_confidence_score
                total_reports = worst.total_reports

        # ── Enrichment-based escalation ───────────────────
        effective_risk = risk

        # Known scanner with high abuse score -> escalate
        if abuse_score >= 80 and effective_risk <= 70:
            effective_risk = max(risk, 71.0)
            actions.append(f"enrichment_escalation:known_scanner={abuse_score}")

        # ── Tiered Response ───────────────────────────────
        if effective_risk > 70:
            # ── High Risk: Block + Incident ───────────────
            actions.append(f"block_ip:{source_ip}")
            actions.append("create_incident_ticket")
            actions.append("notify_soc:warning")
            logger.warning(
                f"[PortScanPlaybook] HIGH RISK ({risk:.1f}): "
                f"Blocking scanner IP {source_ip}"
            )

        elif effective_risk >= 40:
            # ── Medium Risk: Rate-limit + Monitor ─────────
            actions.append(f"rate_limit_ip:{source_ip}")
            actions.append(f"add_to_watchlist:{source_ip}")
            actions.append("notify_soc:info")
            logger.info(
                f"[PortScanPlaybook] MEDIUM RISK ({risk:.1f}): "
                f"Rate-limiting {source_ip}"
            )

        else:
            # ── Low Risk: Log Only ────────────────────────
            actions.append("log_only")
            logger.info(
                f"[PortScanPlaybook] LOW RISK ({risk:.1f}): "
                f"Logging scan from {source_ip}"
            )

        # ── Enrichment-based tags ─────────────────────────
        if total_reports > 50:
            actions.append(f"tag:known_scanner:{source_ip}")

        return actions
