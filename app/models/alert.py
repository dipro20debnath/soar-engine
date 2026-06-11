"""SOAR Engine - Alert Data Models

Defines Pydantic schemas for raw SIEM alerts and normalized alerts.
Supports multiple SIEM formats (Splunk, Elastic SIEM, generic JSON).
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class AlertSeverity(str, Enum):
    """Standardized severity levels (1-5 scale)."""
    INFO = "info"           # 1 - Informational
    LOW = "low"             # 2 - Low risk
    MEDIUM = "medium"       # 3 - Medium risk
    HIGH = "high"           # 4 - High risk
    CRITICAL = "critical"   # 5 - Critical / Emergency


class AlertType(str, Enum):
    """Types of security alerts the SOAR engine handles."""
    BRUTE_FORCE = "brute_force"
    MALWARE_DETECTED = "malware_detected"
    SUSPICIOUS_LOGIN = "suspicious_login"
    PORT_SCAN = "port_scan"
    DATA_EXFILTRATION = "data_exfiltration"
    PHISHING = "phishing"
    UNKNOWN = "unknown"


class AlertStatus(str, Enum):
    """Lifecycle status of an alert in the SOAR pipeline."""
    NEW = "new"                      # Just received
    NORMALIZING = "normalizing"      # Being normalized
    NORMALIZED = "normalized"        # Normalization complete
    ENRICHING = "enriching"          # Threat enrichment in progress
    ENRICHED = "enriched"            # Enrichment complete
    RESPONDING = "responding"        # Playbook executing
    RESPONDED = "responded"          # Automated response complete
    PENDING_APPROVAL = "pending_approval"  # Awaiting human approval
    CLOSED = "closed"                # Fully resolved
    FAILED = "failed"                # Processing failed


class SIEMSource(str, Enum):
    """Supported SIEM sources."""
    SPLUNK = "splunk"
    ELASTIC = "elastic"
    GENERIC = "generic"


class IoC(BaseModel):
    """Indicator of Compromise extracted from an alert."""
    ioc_type: str = Field(..., description="Type: ip, hash, url, domain, email")
    value: str = Field(..., description="The actual IoC value")
    context: str = Field(default="", description="Where this IoC was found in the alert")


class RawAlert(BaseModel):
    """Incoming raw SIEM alert payload. Flexible schema to accept various SIEM formats."""
    source: Optional[str] = Field(default="generic", description="SIEM source identifier")
    payload: dict[str, Any] = Field(..., description="Raw alert JSON payload from SIEM")


class NormalizedAlert(BaseModel):
    """Standardized alert schema after normalization.
    
    All SIEM alerts are converted to this unified format for
    consistent processing through the enrichment and response pipeline.
    """
    # ── Identity ─────────────────────────────────────
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique alert identifier")
    
    # ── Timestamps ───────────────────────────────────
    timestamp: datetime = Field(..., description="When the event occurred (normalized to ISO 8601)")
    received_at: datetime = Field(default_factory=datetime.utcnow, description="When SOAR received this alert")
    
    # ── Classification ───────────────────────────────
    alert_type: AlertType = Field(default=AlertType.UNKNOWN, description="Type of security event")
    severity: AlertSeverity = Field(default=AlertSeverity.MEDIUM, description="Normalized severity level")
    status: AlertStatus = Field(default=AlertStatus.NEW, description="Current processing status")
    
    # ── Network Info ─────────────────────────────────
    source_ip: Optional[str] = Field(default=None, description="Attacker / source IP address")
    dest_ip: Optional[str] = Field(default=None, description="Target / destination IP address")
    target_host: Optional[str] = Field(default=None, description="Target hostname or instance ID")
    
    # ── Event Details ────────────────────────────────
    description: str = Field(default="", description="Human-readable description of the event")
    iocs: list[IoC] = Field(default_factory=list, description="Extracted Indicators of Compromise")
    
    # ── Enrichment Data (populated in Week 2) ────────
    risk_score: Optional[float] = Field(default=None, description="Calculated risk score (0-100)")
    enrichment_data: dict[str, Any] = Field(default_factory=dict, description="Threat intelligence enrichment results")
    
    # ── Response Data (populated in Week 3) ──────────
    playbook_name: Optional[str] = Field(default=None, description="Name of the playbook that handled this alert")
    response_actions: list[str] = Field(default_factory=list, description="List of containment actions taken")
    
    # ── Metadata ─────────────────────────────────────
    siem_source: SIEMSource = Field(default=SIEMSource.GENERIC, description="Which SIEM sent this alert")
    raw_payload: dict[str, Any] = Field(default_factory=dict, description="Original raw payload (preserved for audit)")
    tags: list[str] = Field(default_factory=list, description="Custom tags for categorization")


class AlertSummary(BaseModel):
    """Lightweight alert summary for list views and dashboard."""
    alert_id: str
    timestamp: datetime
    alert_type: AlertType
    severity: AlertSeverity
    status: AlertStatus
    source_ip: Optional[str] = None
    description: str = ""
    risk_score: Optional[float] = None


class AlertStats(BaseModel):
    """Aggregated statistics about processed alerts."""
    total_alerts: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_type: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    avg_risk_score: Optional[float] = None
    last_alert_time: Optional[datetime] = None
