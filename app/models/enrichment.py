"""SOAR Engine - Enrichment Data Models

Defines schemas for threat intelligence enrichment results.
Used in Week 2 when integrating AbuseIPDB and VirusTotal APIs.
"""

from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field


class IPReputation(BaseModel):
    """Result from IP reputation lookup (e.g., AbuseIPDB)."""
    ip_address: str
    abuse_confidence_score: int = Field(default=0, ge=0, le=100, description="Abuse confidence score (0-100)")
    country_code: Optional[str] = None
    isp: Optional[str] = None
    domain: Optional[str] = None
    total_reports: int = 0
    last_reported_at: Optional[datetime] = None
    is_whitelisted: bool = False
    is_tor: bool = False
    source: str = "abuseipdb"
    raw_response: dict[str, Any] = Field(default_factory=dict)


class FileHashResult(BaseModel):
    """Result from file hash lookup (e.g., VirusTotal)."""
    file_hash: str
    hash_type: str = "sha256"  # md5, sha1, sha256
    detection_ratio: Optional[str] = None  # e.g., "45/72"
    malware_family: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    is_malicious: bool = False
    source: str = "virustotal"
    raw_response: dict[str, Any] = Field(default_factory=dict)


class EnrichmentResult(BaseModel):
    """Combined enrichment result for an alert."""
    alert_id: str
    enriched_at: datetime = Field(default_factory=datetime.utcnow)
    ip_results: list[IPReputation] = Field(default_factory=list)
    hash_results: list[FileHashResult] = Field(default_factory=list)
    overall_threat_level: str = "unknown"  # low, medium, high, critical
    confidence: float = 0.0  # 0.0 to 1.0
    notes: list[str] = Field(default_factory=list)
