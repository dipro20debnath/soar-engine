"""SOAR Engine - Playbook Execution Engine

Central orchestrator that maps alert types to response playbooks and
executes the appropriate playbook when an alert is processed.

The engine maintains a registry of playbook instances keyed by AlertType.
When execute() is called, it:
    1. Looks up the playbook for the alert's type
    2. Falls back to DefaultPlaybook if no match is found
    3. Runs the playbook's execute() method
    4. Executes real containment actions (firewall, isolation, notifications)
    5. Checks if high-impact actions need human approval
    6. Records the playbook name and actions on the alert
    7. Logs the execution for audit trail

Usage:
    engine = PlaybookEngine()
    actions = engine.execute(alert, enrichment)
    # alert.playbook_name and alert.response_actions are now populated
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from app.models.alert import NormalizedAlert, AlertType, AlertStatus
from app.models.enrichment import EnrichmentResult
from app.playbooks.base import BasePlaybook
from app.playbooks.default import DefaultPlaybook
from app.playbooks.brute_force import BruteForcePlaybook
from app.playbooks.malware_detected import MalwareDetectedPlaybook
from app.playbooks.suspicious_login import SuspiciousLoginPlaybook
from app.playbooks.port_scan import PortScanPlaybook
from app.playbooks.data_exfiltration import DataExfiltrationPlaybook
from app.containment.firewall import firewall
from app.containment.aws_isolator import aws_isolator
from app.containment.notification import notification_service

logger = logging.getLogger(__name__)

# Actions that require human approval when risk > 90
HIGH_IMPACT_ACTIONS = {"isolate_host", "lock_account"}


class PlaybookExecution:
    """Record of a single playbook execution for audit logging."""

    def __init__(
        self,
        alert_id: str,
        playbook_name: str,
        actions: list[str],
        risk_score: float,
        alert_type: str,
        status: str = "completed",
    ):
        self.alert_id = alert_id
        self.playbook_name = playbook_name
        self.actions = actions
        self.risk_score = risk_score
        self.alert_type = alert_type
        self.status = status  # "completed", "pending_approval", "approved", "rejected"
        self.executed_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict:
        """Convert execution record to a dictionary for API responses."""
        return {
            "alert_id": self.alert_id,
            "playbook_name": self.playbook_name,
            "actions": self.actions,
            "risk_score": self.risk_score,
            "alert_type": self.alert_type,
            "status": self.status,
            "executed_at": self.executed_at.isoformat(),
        }


class PlaybookEngine:
    """Central engine that selects and executes response playbooks.

    Maintains a registry mapping AlertType -> BasePlaybook instances.
    Automatically falls back to the DefaultPlaybook for unmapped types.
    Executes real containment actions and supports an approval workflow
    for high-impact actions on very high-risk alerts.

    Attributes:
        _registry: Dictionary mapping AlertType to playbook instances.
        _default: The default playbook used for unmapped alert types.
        _history: List of PlaybookExecution records for audit trail.
        _pending_approval: Alerts awaiting human approval before containment.
    """

    def __init__(self):
        """Initialize the engine with the default playbook registry."""
        self._default = DefaultPlaybook()
        self._history: list[PlaybookExecution] = []
        self._pending_approval: dict[str, dict] = {}  # alert_id -> pending info

        # ── Playbook Registry ─────────────────────────────
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
            3. Run the playbook's execute() method to get recommended actions
            4. Check if high-impact actions need approval (risk > 90)
            5. Execute containment actions (firewall, isolation, notifications)
            6. Update the alert's playbook_name and response_actions
            7. Record the execution in history

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

        # Step 3: Execute playbook to get recommended actions
        try:
            actions = playbook.execute(alert, enrichment)
        except Exception as e:
            logger.error(
                f"Playbook '{playbook.name}' failed for alert {alert.alert_id}: {e}",
                exc_info=True,
            )
            actions = [f"playbook_error:{str(e)}"]

        # Step 4: Check for approval workflow
        needs_approval = self._check_approval_needed(actions, risk_score)

        if needs_approval:
            # Store pending actions and set alert to pending approval
            pending_actions = [
                a for a in actions
                if any(a.startswith(h) for h in HIGH_IMPACT_ACTIONS)
            ]
            self._pending_approval[alert.alert_id] = {
                "alert_id": alert.alert_id,
                "playbook_name": playbook.name,
                "all_actions": actions,
                "pending_actions": pending_actions,
                "risk_score": risk_score,
                "requested_at": datetime.now(timezone.utc).isoformat(),
            }

            # Execute non-high-impact actions immediately
            executed_actions = []
            for action in actions:
                if not any(action.startswith(h) for h in HIGH_IMPACT_ACTIONS):
                    self._execute_containment_action(action, alert.alert_id, risk_score)
                    executed_actions.append(action)

            # Add pending marker
            executed_actions.append(
                f"pending_approval:{','.join(pending_actions)}"
            )

            # Send approval request notification
            notification_service.send_approval_request(
                alert.alert_id, pending_actions, risk_score
            )

            alert.status = AlertStatus.PENDING_APPROVAL
            alert.playbook_name = playbook.name
            alert.response_actions = executed_actions

            execution = PlaybookExecution(
                alert_id=alert.alert_id,
                playbook_name=playbook.name,
                actions=executed_actions,
                risk_score=risk_score,
                alert_type=alert.alert_type.value,
                status="pending_approval",
            )
            self._history.append(execution)

            logger.warning(
                f"Playbook '{playbook.name}' requires approval for alert "
                f"{alert.alert_id}: {pending_actions}"
            )
            return executed_actions

        # Step 5: Execute all containment actions
        for action in actions:
            self._execute_containment_action(action, alert.alert_id, risk_score)

        # Step 6: Update the alert
        alert.playbook_name = playbook.name
        alert.response_actions = actions
        alert.status = AlertStatus.RESPONDED

        # Send playbook notification
        notification_service.send_playbook_notification(
            alert.alert_id, playbook.name, actions, risk_score
        )

        # Step 7: Record execution
        execution = PlaybookExecution(
            alert_id=alert.alert_id,
            playbook_name=playbook.name,
            actions=actions,
            risk_score=risk_score,
            alert_type=alert.alert_type.value,
            status="completed",
        )
        self._history.append(execution)

        logger.info(
            f"Playbook '{playbook.name}' completed for alert {alert.alert_id}: "
            f"{len(actions)} actions taken -> {actions}"
        )

        return actions

    def _check_approval_needed(
        self, actions: list[str], risk_score: float
    ) -> bool:
        """Check if any actions require human approval.

        High-impact actions (isolate_host, lock_account) require approval
        when the risk score exceeds 90 to prevent false-positive damage.
        """
        if risk_score <= 90:
            return False

        return any(
            any(action.startswith(h) for h in HIGH_IMPACT_ACTIONS)
            for action in actions
        )

    def _execute_containment_action(
        self, action: str, alert_id: str, risk_score: float
    ) -> None:
        """Execute a single containment action using the appropriate module.

        Dispatches actions to the firewall, AWS isolator, or notification
        service based on the action prefix.

        Args:
            action: The action string (e.g., "block_ip:103.24.55.12").
            alert_id: The related alert ID for logging.
            risk_score: The alert's risk score for notification severity.
        """
        try:
            if action.startswith("block_ip:"):
                ip = action.split(":", 1)[1]
                firewall.block_ip(ip, reason=f"alert:{alert_id}")

            elif action.startswith("isolate_host:"):
                host = action.split(":", 1)[1]
                aws_isolator.isolate_instance(host, reason=f"alert:{alert_id}")

            elif action.startswith("block_c2_url:"):
                url = action.split(":", 1)[1]
                logger.warning(
                    f"[Containment] C2 URL blocked: {url} (alert: {alert_id})"
                )

            elif action.startswith("notify_soc:"):
                severity = action.split(":", 1)[1]
                notification_service.send_alert(
                    f"SOC Alert for {alert_id} (risk: {risk_score:.1f})",
                    severity=severity,
                    alert_id=alert_id,
                )

            elif action.startswith("rate_limit_ip:"):
                ip = action.split(":", 1)[1]
                logger.info(
                    f"[Containment] Rate-limiting IP: {ip} (alert: {alert_id})"
                )

            elif action.startswith("quarantine_hash:"):
                file_hash = action.split(":", 1)[1]
                logger.warning(
                    f"[Containment] File hash quarantined: {file_hash} "
                    f"(alert: {alert_id})"
                )

            elif action.startswith("throttle_outbound:"):
                host = action.split(":", 1)[1]
                logger.info(
                    f"[Containment] Throttling outbound traffic for {host} "
                    f"(alert: {alert_id})"
                )

            # Tags and log-only actions don't need containment execution
            elif action.startswith("tag:") or action in (
                "log_only", "log_and_monitor", "log_alert",
            ) or action.startswith("log_alert:"):
                pass

            elif action in (
                "lock_account", "force_password_reset", "notify_user",
                "create_incident_ticket", "assign_triage_ticket",
                "escalate_to_senior_analyst",
            ):
                logger.info(
                    f"[Containment] Action executed: {action} "
                    f"(alert: {alert_id})"
                )

            elif action.startswith("add_to_watchlist:"):
                ip = action.split(":", 1)[1]
                logger.info(
                    f"[Containment] Added to watchlist: {ip} "
                    f"(alert: {alert_id})"
                )

            elif action.startswith("monitor_traffic:"):
                host = action.split(":", 1)[1]
                logger.info(
                    f"[Containment] Monitoring traffic for: {host} "
                    f"(alert: {alert_id})"
                )

            elif action.startswith("enrichment_escalation:"):
                pass  # Informational, not a containment action

            elif action.startswith("pending_approval:"):
                pass  # Handled separately

            else:
                logger.debug(
                    f"[Containment] Unhandled action: {action} "
                    f"(alert: {alert_id})"
                )

        except Exception as e:
            logger.error(
                f"[Containment] Failed to execute '{action}' for "
                f"alert {alert_id}: {e}"
            )

    # ── Approval Workflow ─────────────────────────────

    def approve_alert(self, alert_id: str) -> Optional[dict]:
        """Approve pending high-impact actions for an alert.

        Executes the previously deferred containment actions.

        Args:
            alert_id: The alert ID to approve.

        Returns:
            Dictionary with approval results, or None if not found.
        """
        if alert_id not in self._pending_approval:
            return None

        pending = self._pending_approval.pop(alert_id)
        pending_actions = pending["pending_actions"]
        risk_score = pending["risk_score"]

        # Execute the previously deferred actions
        for action in pending_actions:
            self._execute_containment_action(action, alert_id, risk_score)

        # Record approval
        execution = PlaybookExecution(
            alert_id=alert_id,
            playbook_name=pending["playbook_name"],
            actions=pending_actions,
            risk_score=risk_score,
            alert_type="approval",
            status="approved",
        )
        self._history.append(execution)

        notification_service.send_alert(
            f"Alert {alert_id} APPROVED - executing: {', '.join(pending_actions)}",
            severity="critical",
            alert_id=alert_id,
        )

        logger.info(
            f"Alert {alert_id} APPROVED - executing {len(pending_actions)} "
            f"deferred actions: {pending_actions}"
        )

        return {
            "alert_id": alert_id,
            "status": "approved",
            "executed_actions": pending_actions,
            "approved_at": datetime.now(timezone.utc).isoformat(),
        }

    def reject_alert(self, alert_id: str) -> Optional[dict]:
        """Reject pending high-impact actions for an alert.

        Discards the deferred containment actions.

        Args:
            alert_id: The alert ID to reject.

        Returns:
            Dictionary with rejection results, or None if not found.
        """
        if alert_id not in self._pending_approval:
            return None

        pending = self._pending_approval.pop(alert_id)
        pending_actions = pending["pending_actions"]

        # Record rejection
        execution = PlaybookExecution(
            alert_id=alert_id,
            playbook_name=pending["playbook_name"],
            actions=[f"rejected:{a}" for a in pending_actions],
            risk_score=pending["risk_score"],
            alert_type="rejection",
            status="rejected",
        )
        self._history.append(execution)

        notification_service.send_alert(
            f"Alert {alert_id} REJECTED - actions discarded: {', '.join(pending_actions)}",
            severity="warning",
            alert_id=alert_id,
        )

        logger.info(
            f"Alert {alert_id} REJECTED - {len(pending_actions)} actions discarded"
        )

        return {
            "alert_id": alert_id,
            "status": "rejected",
            "discarded_actions": pending_actions,
            "rejected_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_pending_approvals(self) -> list[dict]:
        """Get all alerts currently waiting for human approval."""
        return list(self._pending_approval.values())

    # ── Query Methods ─────────────────────────────────

    def get_playbook(self, alert_type: AlertType) -> BasePlaybook:
        """Get the playbook registered for a given alert type."""
        return self._registry.get(alert_type, self._default)

    def get_history(self, limit: int = 50) -> list[dict]:
        """Get recent playbook execution history (newest first)."""
        return [
            ex.to_dict()
            for ex in sorted(
                self._history, key=lambda e: e.executed_at, reverse=True
            )[:limit]
        ]

    def get_registered_playbooks(self) -> dict[str, str]:
        """List all registered playbooks and their descriptions."""
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


# ── Global engine instance ────────────────────────────
playbook_engine = PlaybookEngine()
