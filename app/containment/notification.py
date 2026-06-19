"""SOAR Engine - Notification Service

Simulates sending notifications to the SOC team via various channels.
In production, this would integrate with Slack, email, PagerDuty, etc.

All notifications are logged for audit trail.
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class Notification:
    """Record of a single notification sent."""

    def __init__(
        self,
        message: str,
        severity: str = "info",
        channel: str = "soc_team",
        alert_id: str = "",
    ):
        self.message = message
        self.severity = severity  # info, warning, critical
        self.channel = channel
        self.alert_id = alert_id
        self.timestamp = datetime.now(timezone.utc)
        self.delivered = True  # Always true in simulation

    def to_dict(self) -> dict:
        return {
            "message": self.message,
            "severity": self.severity,
            "channel": self.channel,
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.isoformat(),
            "delivered": self.delivered,
        }


class NotificationService:
    """Simulated SOC team notification service.

    Logs notifications to console and maintains an in-memory history.
    In production, replace with real integrations:
        - Slack webhook for real-time alerts
        - Email via SMTP for detailed reports
        - PagerDuty for on-call escalation
        - Microsoft Teams webhook

    Usage:
        notifier = NotificationService()
        notifier.send_alert("Brute force attack detected", "critical", alert_id="abc-123")
    """

    def __init__(self):
        """Initialize the notification service."""
        self._history: list[Notification] = []
        logger.info("NotificationService initialized (simulation mode)")

    def send_alert(
        self,
        message: str,
        severity: str = "info",
        channel: str = "soc_team",
        alert_id: str = "",
    ) -> bool:
        """Send a notification to the SOC team.

        Args:
            message: The notification message text.
            severity: Priority level - "info", "warning", or "critical".
            channel: Destination channel (e.g., "soc_team", "management").
            alert_id: Related alert ID for cross-referencing.

        Returns:
            True if notification was sent successfully.
        """
        notification = Notification(message, severity, channel, alert_id)
        self._history.append(notification)

        # Format log message based on severity
        if severity == "critical":
            logger.critical(
                f"[NOTIFICATION] [{severity.upper()}] [{channel}] "
                f"Alert: {alert_id} | {message}"
            )
        elif severity == "warning":
            logger.warning(
                f"[NOTIFICATION] [{severity.upper()}] [{channel}] "
                f"Alert: {alert_id} | {message}"
            )
        else:
            logger.info(
                f"[NOTIFICATION] [{severity.upper()}] [{channel}] "
                f"Alert: {alert_id} | {message}"
            )

        return True

    def send_playbook_notification(
        self,
        alert_id: str,
        playbook_name: str,
        actions: list[str],
        risk_score: float,
    ) -> bool:
        """Send a notification about playbook execution results.

        Args:
            alert_id: The alert that triggered the playbook.
            playbook_name: Name of the playbook that was executed.
            actions: List of actions taken by the playbook.
            risk_score: The alert's risk score.

        Returns:
            True if notification was sent successfully.
        """
        severity = "critical" if risk_score > 75 else "warning" if risk_score > 40 else "info"
        action_list = ", ".join(actions[:5])  # Limit to first 5 actions
        if len(actions) > 5:
            action_list += f" (+{len(actions) - 5} more)"

        message = (
            f"Playbook '{playbook_name}' executed for alert {alert_id} "
            f"(risk: {risk_score:.1f}). Actions: {action_list}"
        )

        return self.send_alert(message, severity, "soc_team", alert_id)

    def send_approval_request(
        self,
        alert_id: str,
        pending_actions: list[str],
        risk_score: float,
    ) -> bool:
        """Send a notification requesting human approval for high-risk actions.

        Args:
            alert_id: The alert requiring approval.
            pending_actions: Actions waiting for human approval.
            risk_score: The alert's risk score.

        Returns:
            True if notification was sent successfully.
        """
        action_list = ", ".join(pending_actions)
        message = (
            f"APPROVAL REQUIRED: Alert {alert_id} (risk: {risk_score:.1f}) "
            f"has high-impact actions pending: {action_list}. "
            f"Use POST /api/playbooks/approve/{alert_id} to approve."
        )

        return self.send_alert(message, "critical", "soc_team", alert_id)

    def get_history(self, limit: int = 50) -> list[dict]:
        """Get recent notification history (newest first)."""
        return [
            n.to_dict()
            for n in sorted(
                self._history, key=lambda x: x.timestamp, reverse=True
            )[:limit]
        ]

    @property
    def total_sent(self) -> int:
        """Total number of notifications sent."""
        return len(self._history)

    def clear_history(self) -> None:
        """Clear notification history."""
        self._history.clear()
        logger.info("[NotificationService] History cleared")


# ── Global notification service instance ──────────────
notification_service = NotificationService()
