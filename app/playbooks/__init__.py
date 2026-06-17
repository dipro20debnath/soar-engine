"""SOAR Engine - Playbooks Package

Contains all response playbooks and the base interface.
Each playbook defines automated actions for a specific alert type.

Available playbooks:
    - BruteForcePlaybook: Handles brute-force login attacks
    - MalwareDetectedPlaybook: Handles malware detection events
    - SuspiciousLoginPlaybook: Handles suspicious login attempts
    - PortScanPlaybook: Handles port scanning / reconnaissance
    - DataExfiltrationPlaybook: Handles data exfiltration / data theft
    - DefaultPlaybook: Fallback for unhandled alert types
"""

from app.playbooks.base import BasePlaybook
from app.playbooks.default import DefaultPlaybook
from app.playbooks.brute_force import BruteForcePlaybook
from app.playbooks.malware_detected import MalwareDetectedPlaybook
from app.playbooks.suspicious_login import SuspiciousLoginPlaybook
from app.playbooks.port_scan import PortScanPlaybook
from app.playbooks.data_exfiltration import DataExfiltrationPlaybook

__all__ = [
    "BasePlaybook",
    "DefaultPlaybook",
    "BruteForcePlaybook",
    "MalwareDetectedPlaybook",
    "SuspiciousLoginPlaybook",
    "PortScanPlaybook",
    "DataExfiltrationPlaybook",
]
