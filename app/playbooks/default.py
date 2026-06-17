"""SOAR Engine - Default Fallback Playbook

Used when no specific playbook is registered for an alert type.
Performs basic triage actions: logging and ticket assignment.
"""

import logging
from typing import Optional

from app.models.alert import NormalizedAlert
from app.models.enrichment import EnrichmentResult
from app.playbooks.base import BasePlaybook

logger = logging.getLogger(__name__)


class DefaultPlaybook(BasePlaybook):
    """Fallback playbook for unhandled alert types.

    Actions by risk level:
        - Any risk: Log the alert details
        - Risk >= 50: Assign a triage ticket to the SOC team
        - Risk >= 75: Escalate to senior analyst
    """

    @property
    def name(self) -> str:
        return "default_triage"

    @property
    def description(self) -> str:
        return "Default triage playbook for unhandled alert types"

    def execute(
        self,
        alert: NormalizedAlert,
        enrichment: Optional[EnrichmentResult] = None,
    ) -> list[str]:
        """Execute default triage actions based on risk score."""
        risk = self._get_risk_score(alert)
        actions = []

        # Always log the alert
        actions.append(f"log_alert:{alert.alert_id}")
        logger.info(
            f"[DefaultPlaybook] Alert {alert.alert_id} "
            f"(type={alert.alert_type.value}, risk={risk:.1f}) logged for triage"
        )

        # Medium risk and above: assign a ticket
        if risk >= 50:
            actions.append("assign_triage_ticket")
            logger.info(
                f"[DefaultPlaybook] Triage ticket assigned for alert {alert.alert_id}"
            )

        # High risk: escalate
        if risk >= 75:
            actions.append("escalate_to_senior_analyst")
            logger.warning(
                f"[DefaultPlaybook] Alert {alert.alert_id} escalated "
                f"to senior analyst (risk={risk:.1f})"
            )

        return actions
