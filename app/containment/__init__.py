"""SOAR Engine - Containment Package

Provides simulated containment modules for automated incident response.
In production, these would integrate with real infrastructure APIs.

Available modules:
    - SimulatedFirewall: IP blocking/unblocking with in-memory blocklist
    - SimulatedAWSIsolator: EC2 instance isolation via quarantine security group
    - NotificationService: SOC team notifications (console + log based)
"""

from app.containment.firewall import SimulatedFirewall, firewall
from app.containment.aws_isolator import SimulatedAWSIsolator, aws_isolator
from app.containment.notification import NotificationService, notification_service

__all__ = [
    "SimulatedFirewall",
    "firewall",
    "SimulatedAWSIsolator",
    "aws_isolator",
    "NotificationService",
    "notification_service",
]
