"""SOAR Engine - Simulated Firewall Containment Module

Provides an in-memory firewall simulation for IP blocking/unblocking.
In production, this would integrate with a real firewall API
(e.g., AWS Security Groups, iptables, Palo Alto).

All actions are logged for audit trail.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


class FirewallAction:
    """Record of a single firewall action for audit logging."""

    def __init__(self, action: str, ip_address: str, reason: str = ""):
        self.action = action  # "block" or "unblock"
        self.ip_address = ip_address
        self.reason = reason
        self.timestamp = datetime.now(timezone.utc)

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "ip_address": self.ip_address,
            "reason": self.reason,
            "timestamp": self.timestamp.isoformat(),
        }


class SimulatedFirewall:
    """Simulated firewall with an in-memory IP blocklist.

    Provides methods to block/unblock IPs and query the blocklist.
    All operations are logged for audit trail.

    In production, replace method bodies with real firewall API calls
    (e.g., boto3 for AWS Security Groups, or REST API for Palo Alto).
    """

    def __init__(self):
        """Initialize the firewall with an empty blocklist."""
        self._blocklist: dict[str, dict] = {}  # ip -> metadata
        self._action_log: list[FirewallAction] = []
        logger.info("SimulatedFirewall initialized (in-memory blocklist)")

    def block_ip(self, ip_address: str, reason: str = "automated") -> bool:
        """Block an IP address in the firewall.

        Args:
            ip_address: The IPv4 address to block.
            reason: Why this IP is being blocked (for audit trail).

        Returns:
            True if newly blocked, False if already blocked.
        """
        if ip_address in self._blocklist:
            logger.info(f"[Firewall] IP {ip_address} is already blocked")
            return False

        self._blocklist[ip_address] = {
            "blocked_at": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
        }

        action = FirewallAction("block", ip_address, reason)
        self._action_log.append(action)

        logger.warning(
            f"[Firewall] BLOCKED IP: {ip_address} | Reason: {reason}"
        )
        return True

    def unblock_ip(self, ip_address: str, reason: str = "manual") -> bool:
        """Unblock an IP address from the firewall.

        Args:
            ip_address: The IPv4 address to unblock.
            reason: Why this IP is being unblocked.

        Returns:
            True if unblocked, False if not found in blocklist.
        """
        if ip_address not in self._blocklist:
            logger.info(f"[Firewall] IP {ip_address} is not in the blocklist")
            return False

        del self._blocklist[ip_address]

        action = FirewallAction("unblock", ip_address, reason)
        self._action_log.append(action)

        logger.info(
            f"[Firewall] UNBLOCKED IP: {ip_address} | Reason: {reason}"
        )
        return True

    def is_blocked(self, ip_address: str) -> bool:
        """Check if an IP address is currently blocked.

        Args:
            ip_address: The IPv4 address to check.

        Returns:
            True if blocked, False otherwise.
        """
        return ip_address in self._blocklist

    def get_blocklist(self) -> dict[str, dict]:
        """Get the full current blocklist.

        Returns:
            Dictionary mapping blocked IPs to their metadata
            (blocked_at timestamp and reason).
        """
        return dict(self._blocklist)

    def get_action_log(self, limit: int = 50) -> list[dict]:
        """Get recent firewall action log.

        Args:
            limit: Maximum number of records to return.

        Returns:
            List of action records (newest first).
        """
        return [
            a.to_dict()
            for a in sorted(
                self._action_log, key=lambda x: x.timestamp, reverse=True
            )[:limit]
        ]

    @property
    def blocked_count(self) -> int:
        """Total number of currently blocked IPs."""
        return len(self._blocklist)

    def clear(self) -> None:
        """Clear the entire blocklist and action log."""
        self._blocklist.clear()
        self._action_log.clear()
        logger.info("[Firewall] Blocklist and action log cleared")


# ── Global firewall instance ─────────────────────────
# Single instance shared across the application
firewall = SimulatedFirewall()
