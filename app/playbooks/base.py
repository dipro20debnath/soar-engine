"""SOAR Engine - Base Playbook Interface

Defines the abstract base class that all response playbooks must implement.
Each playbook encapsulates the automated response logic for a specific
type of security incident (e.g., brute force, malware, suspicious login).

Usage:
    class MyPlaybook(BasePlaybook):
        name = "my_response"
        description = "Handles my alert type"

        def execute(self, alert, enrichment=None):
            actions = []
            # ... decision logic based on risk score ...
            return actions
"""

import logging
from abc import ABC, abstractmethod
from typing import Optional

from app.models.alert import NormalizedAlert
from app.models.enrichment import EnrichmentResult

logger = logging.getLogger(__name__)


class BasePlaybook(ABC):
    """Abstract base class for SOAR response playbooks.

    Every playbook must define:
        - name: A short identifier (e.g., "brute_force_response")
        - description: A human-readable summary of what the playbook does
        - execute(): The core method that evaluates the alert and returns actions

    The execute() method receives a NormalizedAlert (always) and an optional
    EnrichmentResult (available if enrichment was successful). It should
    return a list of action strings describing what was done.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier for this playbook (e.g., 'brute_force_response')."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of the playbook's purpose."""
        ...

    @abstractmethod
    def execute(
        self,
        alert: NormalizedAlert,
        enrichment: Optional[EnrichmentResult] = None,
    ) -> list[str]:
        """Execute the playbook against an alert.

        Args:
            alert: The normalized, enriched alert to respond to.
            enrichment: Optional enrichment data (IP reputation, hash results).

        Returns:
            A list of action strings describing the containment actions taken.
            Example: ["block_ip:103.24.55.12", "notify_soc:critical"]
        """
        ...

    def _get_risk_score(self, alert: NormalizedAlert) -> float:
        """Helper to safely retrieve the alert's risk score.

        Returns 0.0 if no risk score has been calculated yet.
        """
        return alert.risk_score if alert.risk_score is not None else 0.0

    def __repr__(self) -> str:
        return f"<Playbook: {self.name}>"
