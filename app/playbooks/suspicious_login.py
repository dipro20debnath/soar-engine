"""SOAR Engine - Suspicious Login Response Playbook

Automated response for suspicious login events (unusual geo-location,
impossible travel, or after-hours access).

Actions escalate based on the alert's risk score:
    - Low risk  (< 40):  Log only
    - Medium    (40-70):  Force password reset + notify user
    - High risk (> 70):   Lock account + block IP + notify SOC
"""

import logging
from typing import Optional

from app.models.alert import NormalizedAlert
from app.models.enrichment import EnrichmentResult
from app.playbooks.base import BasePlaybook

logger = logging.getLogger(__name__)


class SuspiciousLoginPlaybook(BasePlaybook):
    """Response playbook for suspicious login attempts.

    Evaluates risk score and source IP reputation to determine
    whether the login should be allowed, the user warned, or
    the account locked.
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
        """Execute suspicious login response based on risk score.

        Args:
            alert: The normalized alert (type should be SUSPICIOUS_LOGIN).
            enrichment: Optional enrichment data with IP reputation.

        Returns:
            List of actions taken.
        """
        risk = self._get_risk_score(alert)
        source_ip = alert.source_ip or "unknown"
        actions = []

        if risk > 70:
            # ── High Risk: Lock Account + Block IP ────────
            actions.append("lock_account")
            actions.append(f"block_ip:{source_ip}")
            actions.append("notify_soc:critical")
            logger.warning(
                f"[SuspiciousLoginPlaybook] HIGH RISK ({risk:.1f}): "
                f"Locking account and blocking IP {source_ip}"
            )

        elif risk >= 40:
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

        return actions
