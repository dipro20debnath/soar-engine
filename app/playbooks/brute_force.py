"""SOAR Engine - Brute Force Response Playbook

Automated response for brute-force login attacks.
Actions escalate based on the alert's risk score:
    - Low risk  (< 30):  Log only
    - Medium    (30-75):  Watch-list the IP + notify SOC
    - High risk (> 75):   Block IP in firewall + send critical alert
"""

import logging
from typing import Optional

from app.models.alert import NormalizedAlert
from app.models.enrichment import EnrichmentResult
from app.playbooks.base import BasePlaybook

logger = logging.getLogger(__name__)


class BruteForcePlaybook(BasePlaybook):
    """Response playbook for brute-force login attempts.

    Evaluates the risk score and source IP to decide on
    proportional containment actions.
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
        """Execute brute-force response based on risk score.

        Args:
            alert: The normalized alert (type should be BRUTE_FORCE).
            enrichment: Optional enrichment data with IP reputation.

        Returns:
            List of actions taken.
        """
        risk = self._get_risk_score(alert)
        source_ip = alert.source_ip or "unknown"
        actions = []

        if risk > 75:
            # ── High Risk: Block + Alert ──────────────────
            actions.append(f"block_ip:{source_ip}")
            actions.append("notify_soc:critical")
            logger.warning(
                f"[BruteForcePlaybook] HIGH RISK ({risk:.1f}): "
                f"Blocking IP {source_ip} and sending critical alert"
            )

        elif risk >= 30:
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

        return actions
