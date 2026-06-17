"""SOAR Engine - Playbook Execution Engine

Central orchestrator that maps alert types to response playbooks and
executes the appropriate playbook when an alert is processed.

The engine maintains a registry of playbook instances keyed by AlertType.
When execute() is called, it:
    1. Looks up the playbook for the alert's type
    2. Falls back to DefaultPlaybook if no match is found
    3. Runs the playbook's execute() method
    4. Records the playbook name and actions on the alert
    5. Logs the execution for audit trail

Usage:
    engine = PlaybookEngine()
    actions = engine.execute(alert, enrichment)
    # alert.playbook_name and alert.response_actions are now populated
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from app.models.alert import NormalizedAlert, AlertType
from app.models.enrichment import EnrichmentResult
from app.playbooks.base import BasePlaybook
from app.playbooks.default import DefaultPlaybook
from app.playbooks.brute_force import BruteForcePlaybook
from app.playbooks.malware_detected import MalwareDetectedPlaybook
from app.playbooks.suspicious_login import SuspiciousLoginPlaybook
from app.playbooks.port_scan import PortScanPlaybook
from app.playbooks.data_exfiltration import DataExfiltrationPlaybook

logger = logging.getLogger(__name__)


class PlaybookExecution:
    """Record of a single playbook execution for audit logging."""

    def __init__(
        self,
        alert_id: str,
        playbook_name: str,
        actions: list[str],
        risk_score: float,
        alert_type: str,
    ):
        self.alert_id = alert_id
        self.playbook_name = playbook_name
        self.actions = actions
        self.risk_score = risk_score
        self.alert_type = alert_type
        self.executed_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict:
        """Convert execution record to a dictionary for API responses."""
        return {
            "alert_id": self.alert_id,
            "playbook_name": self.playbook_name,
            "actions": self.actions,
            "risk_score": self.risk_score,
            "alert_type": self.alert_type,
            "executed_at": self.executed_at.isoformat(),
        }


class PlaybookEngine:
    """Central engine that selects and executes response playbooks.

    Maintains a registry mapping AlertType -> BasePlaybook instances.
    Automatically falls back to the DefaultPlaybook for unmapped types.

    Attributes:
        _registry: Dictionary mapping AlertType to playbook instances.
        _default: The default playbook used for unmapped alert types.
        _history: List of PlaybookExecution records for audit trail.
    """

    def __init__(self):
        """Initialize the engine with the default playbook registry."""
        self._default = DefaultPlaybook()
        self._history: list[PlaybookExecution] = []

        # ── Playbook Registry ─────────────────────────────
        # Maps each AlertType to its dedicated playbook.
        # Alert types without a mapping will use the DefaultPlaybook.
        self._registry: dict[AlertType, BasePlaybook] = {
            AlertType.BRUTE_FORCE: BruteForcePlaybook(),
            AlertType.MALWARE_DETECTED: MalwareDetectedPlaybook(),
            AlertType.SUSPICIOUS_LOGIN: SuspiciousLoginPlaybook(),
            AlertType.PORT_SCAN: PortScanPlaybook(),
            AlertType.DATA_EXFILTRATION: DataExfiltrationPlaybook(),
        }

        registered_types = [at.value for at in self._registry]
        logger.info(
            f"PlaybookEngine initialized with {len(self._registry)} playbooks: "
            f"{registered_types}"
        )

    def execute(
        self,
        alert: NormalizedAlert,
        enrichment: Optional[EnrichmentResult] = None,
    ) -> list[str]:
        """Execute the appropriate playbook for an alert.

        Steps:
            1. Look up the playbook by alert_type
            2. Fall back to DefaultPlaybook if not found
            3. Run the playbook's execute() method
            4. Update the alert's playbook_name and response_actions
            5. Record the execution in history

        Args:
            alert: The normalized (and ideally enriched) alert.
            enrichment: Optional enrichment data from threat intel APIs.

        Returns:
            List of action strings describing what was done.
        """
        # Step 1-2: Select playbook
        playbook = self._registry.get(alert.alert_type, self._default)
        risk_score = alert.risk_score if alert.risk_score is not None else 0.0

        logger.info(
            f"Executing playbook '{playbook.name}' for alert {alert.alert_id} "
            f"(type={alert.alert_type.value}, risk={risk_score:.1f})"
        )

        # Step 3: Execute
        try:
            actions = playbook.execute(alert, enrichment)
        except Exception as e:
            logger.error(
                f"Playbook '{playbook.name}' failed for alert {alert.alert_id}: {e}",
                exc_info=True,
            )
            actions = [f"playbook_error:{str(e)}"]

        # Step 4: Update the alert
        alert.playbook_name = playbook.name
        alert.response_actions = actions

        # Step 5: Record execution
        execution = PlaybookExecution(
            alert_id=alert.alert_id,
            playbook_name=playbook.name,
            actions=actions,
            risk_score=risk_score,
            alert_type=alert.alert_type.value,
        )
        self._history.append(execution)

        logger.info(
            f"Playbook '{playbook.name}' completed for alert {alert.alert_id}: "
            f"{len(actions)} actions taken -> {actions}"
        )

        return actions

    def get_playbook(self, alert_type: AlertType) -> BasePlaybook:
        """Get the playbook registered for a given alert type.

        Args:
            alert_type: The alert type to look up.

        Returns:
            The registered playbook, or the default if not found.
        """
        return self._registry.get(alert_type, self._default)

    def get_history(self, limit: int = 50) -> list[dict]:
        """Get recent playbook execution history.

        Args:
            limit: Maximum number of records to return.

        Returns:
            List of execution records as dictionaries (newest first).
        """
        return [
            ex.to_dict()
            for ex in sorted(
                self._history, key=lambda e: e.executed_at, reverse=True
            )[:limit]
        ]

    def get_registered_playbooks(self) -> dict[str, str]:
        """List all registered playbooks and their descriptions.

        Returns:
            Dictionary mapping playbook names to descriptions.
        """
        result = {}
        for alert_type, playbook in self._registry.items():
            result[alert_type.value] = {
                "playbook_name": playbook.name,
                "description": playbook.description,
            }
        result["_default"] = {
            "playbook_name": self._default.name,
            "description": self._default.description,
        }
        return result

    @property
    def history_count(self) -> int:
        """Total number of playbook executions recorded."""
        return len(self._history)

    def clear_history(self) -> None:
        """Clear all execution history."""
        self._history.clear()
        logger.info("Playbook execution history cleared")
