"""SOAR Engine - Simulated AWS EC2 Isolator

Simulates isolating compromised EC2 instances by changing their
security group to a restrictive "quarantine" group that blocks
all inbound/outbound traffic.

In production, this would use boto3 to modify AWS Security Groups.
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class IsolationRecord:
    """Record of a single host isolation action."""

    def __init__(self, instance_id: str, action: str, reason: str = ""):
        self.instance_id = instance_id
        self.action = action  # "isolate" or "restore"
        self.reason = reason
        self.timestamp = datetime.now(timezone.utc)
        self.success = True

    def to_dict(self) -> dict:
        return {
            "instance_id": self.instance_id,
            "action": self.action,
            "reason": self.reason,
            "success": self.success,
            "timestamp": self.timestamp.isoformat(),
        }


class SimulatedAWSIsolator:
    """Simulated AWS EC2 instance isolator.

    Maintains an in-memory set of isolated instances.
    In production, this would:
        1. Store the current security group
        2. Replace it with a quarantine SG that blocks all traffic
        3. Tag the instance as "quarantined"

    Usage:
        isolator = SimulatedAWSIsolator()
        result = isolator.isolate_instance("web-server-01")
        # result == True if newly isolated
    """

    def __init__(self):
        """Initialize the isolator with no isolated instances."""
        self._isolated: dict[str, dict] = {}  # instance_id -> metadata
        self._action_log: list[IsolationRecord] = []
        logger.info("SimulatedAWSIsolator initialized")

    def isolate_instance(
        self, instance_id: str, reason: str = "automated"
    ) -> bool:
        """Isolate an EC2 instance by applying quarantine security group.

        Args:
            instance_id: The hostname or EC2 instance ID to isolate.
            reason: Why this instance is being isolated.

        Returns:
            True if newly isolated, False if already isolated.
        """
        if instance_id in self._isolated:
            logger.info(
                f"[AWSIsolator] Instance {instance_id} is already isolated"
            )
            return False

        self._isolated[instance_id] = {
            "isolated_at": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "original_security_group": "sg-default-simulated",
            "quarantine_security_group": "sg-quarantine-block-all",
        }

        record = IsolationRecord(instance_id, "isolate", reason)
        self._action_log.append(record)

        logger.warning(
            f"[AWSIsolator] ISOLATED instance: {instance_id} | "
            f"Reason: {reason} | "
            f"Security group changed to sg-quarantine-block-all"
        )
        return True

    def restore_instance(
        self, instance_id: str, reason: str = "manual"
    ) -> bool:
        """Restore an isolated instance to its original security group.

        Args:
            instance_id: The hostname or EC2 instance ID to restore.
            reason: Why this instance is being restored.

        Returns:
            True if restored, False if not found in isolated list.
        """
        if instance_id not in self._isolated:
            logger.info(
                f"[AWSIsolator] Instance {instance_id} is not isolated"
            )
            return False

        del self._isolated[instance_id]

        record = IsolationRecord(instance_id, "restore", reason)
        self._action_log.append(record)

        logger.info(
            f"[AWSIsolator] RESTORED instance: {instance_id} | "
            f"Reason: {reason} | "
            f"Security group restored to original"
        )
        return True

    def is_isolated(self, instance_id: str) -> bool:
        """Check if an instance is currently isolated."""
        return instance_id in self._isolated

    def get_isolated_instances(self) -> dict[str, dict]:
        """Get all currently isolated instances and their metadata."""
        return dict(self._isolated)

    def get_action_log(self, limit: int = 50) -> list[dict]:
        """Get recent isolation action log (newest first)."""
        return [
            r.to_dict()
            for r in sorted(
                self._action_log, key=lambda x: x.timestamp, reverse=True
            )[:limit]
        ]

    @property
    def isolated_count(self) -> int:
        """Total number of currently isolated instances."""
        return len(self._isolated)

    def clear(self) -> None:
        """Clear all isolation records."""
        self._isolated.clear()
        self._action_log.clear()
        logger.info("[AWSIsolator] Isolation records cleared")


# ── Global isolator instance ─────────────────────────
aws_isolator = SimulatedAWSIsolator()
