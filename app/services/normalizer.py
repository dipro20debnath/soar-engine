"""SOAR Engine - Alert Normalization Service

Normalizes incoming SIEM alerts from various sources (Splunk, Elastic, generic)
into a unified NormalizedAlert schema. Handles:
- Timestamp normalization (various formats → ISO 8601)
- IoC extraction (IP addresses, file hashes, URLs, domains, emails)
- Severity mapping (different SIEM scales → unified 1-5)
- Alert type classification
"""

import re
import logging
from datetime import datetime
from typing import Any, Optional

from dateutil import parser as date_parser

from app.models.alert import (
    NormalizedAlert,
    AlertType,
    AlertSeverity,
    AlertStatus,
    SIEMSource,
    IoC,
)

logger = logging.getLogger(__name__)


# ── Regex Patterns for IoC Extraction ────────────────────

# IPv4 Address pattern
IPV4_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

# MD5 hash (32 hex characters)
MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')

# SHA-1 hash (40 hex characters)
SHA1_PATTERN = re.compile(r'\b[a-fA-F0-9]{40}\b')

# SHA-256 hash (64 hex characters)
SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')

# URL pattern
URL_PATTERN = re.compile(
    r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w.-]*(?:\?\S*)?'
)

# Email pattern
EMAIL_PATTERN = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
)

# Domain pattern
DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
    r'(?:[a-zA-Z]{2,})\b'
)


# ── Severity Mapping Tables ──────────────────────────────

# Splunk severity levels → normalized
SPLUNK_SEVERITY_MAP = {
    "informational": AlertSeverity.INFO,
    "info": AlertSeverity.INFO,
    "low": AlertSeverity.LOW,
    "notable": AlertSeverity.MEDIUM,
    "medium": AlertSeverity.MEDIUM,
    "high": AlertSeverity.HIGH,
    "critical": AlertSeverity.CRITICAL,
    "urgent": AlertSeverity.CRITICAL,
}

# Elastic severity levels → normalized
ELASTIC_SEVERITY_MAP = {
    1: AlertSeverity.INFO,
    2: AlertSeverity.LOW,
    3: AlertSeverity.MEDIUM,
    4: AlertSeverity.HIGH,
    5: AlertSeverity.CRITICAL,
    "low": AlertSeverity.LOW,
    "medium": AlertSeverity.MEDIUM,
    "high": AlertSeverity.HIGH,
    "critical": AlertSeverity.CRITICAL,
}

# Generic keyword → alert type mapping
ALERT_TYPE_KEYWORDS = {
    AlertType.BRUTE_FORCE: ["brute", "bruteforce", "brute_force", "failed login", "authentication failure", "login attempt"],
    AlertType.MALWARE_DETECTED: ["malware", "virus", "trojan", "ransomware", "malicious file", "infected"],
    AlertType.SUSPICIOUS_LOGIN: ["suspicious login", "unusual login", "impossible travel", "geo anomaly", "unauthorized access"],
    AlertType.PORT_SCAN: ["port scan", "portscan", "network scan", "reconnaissance", "nmap"],
    AlertType.DATA_EXFILTRATION: ["exfiltration", "data leak", "data transfer", "unusual upload"],
    AlertType.PHISHING: ["phishing", "spear phishing", "social engineering", "suspicious email"],
}


def extract_iocs(data: dict[str, Any]) -> list[IoC]:
    """Extract all Indicators of Compromise from alert data.
    
    Scans all string values in the payload recursively for:
    - IP addresses
    - File hashes (MD5, SHA-1, SHA-256)
    - URLs
    - Email addresses
    
    Args:
        data: The alert payload dictionary to scan.
        
    Returns:
        List of extracted IoC objects with type and context.
    """
    iocs = []
    text_blob = _flatten_to_text(data)
    
    # Extract IPs (exclude common private/localhost IPs for cleaner results)
    for match in IPV4_PATTERN.finditer(text_blob):
        ip = match.group()
        if not _is_private_ip(ip):
            iocs.append(IoC(ioc_type="ip", value=ip, context="Extracted from alert payload"))
    
    # Extract file hashes (check longest first to avoid substring matches)
    seen_hashes = set()
    for match in SHA256_PATTERN.finditer(text_blob):
        h = match.group().lower()
        if h not in seen_hashes:
            iocs.append(IoC(ioc_type="hash_sha256", value=h, context="SHA-256 hash found in payload"))
            seen_hashes.add(h)
    
    for match in SHA1_PATTERN.finditer(text_blob):
        h = match.group().lower()
        if h not in seen_hashes and not any(h in s for s in seen_hashes):
            iocs.append(IoC(ioc_type="hash_sha1", value=h, context="SHA-1 hash found in payload"))
            seen_hashes.add(h)
    
    for match in MD5_PATTERN.finditer(text_blob):
        h = match.group().lower()
        if h not in seen_hashes and not any(h in s for s in seen_hashes):
            iocs.append(IoC(ioc_type="hash_md5", value=h, context="MD5 hash found in payload"))
            seen_hashes.add(h)
    
    # Extract URLs
    for match in URL_PATTERN.finditer(text_blob):
        iocs.append(IoC(ioc_type="url", value=match.group(), context="URL found in payload"))
    
    # Extract emails
    for match in EMAIL_PATTERN.finditer(text_blob):
        iocs.append(IoC(ioc_type="email", value=match.group(), context="Email found in payload"))
    
    return iocs


def _flatten_to_text(data: Any, prefix: str = "") -> str:
    """Recursively flatten a dictionary into a single text blob for regex scanning."""
    parts = []
    if isinstance(data, dict):
        for key, value in data.items():
            parts.append(f"{key}: {_flatten_to_text(value, prefix=key)}")
    elif isinstance(data, list):
        for item in data:
            parts.append(_flatten_to_text(item, prefix))
    elif isinstance(data, str):
        parts.append(data)
    elif data is not None:
        parts.append(str(data))
    return " ".join(parts)


def _is_private_ip(ip: str) -> bool:
    """Check if an IP address is private/reserved (RFC 1918)."""
    octets = ip.split(".")
    if len(octets) != 4:
        return True
    first, second = int(octets[0]), int(octets[1])
    # 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8
    if first == 10:
        return True
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 192 and second == 168:
        return True
    if first == 127:
        return True
    if first == 0 or first == 255:
        return True
    return False


def _classify_alert_type(data: dict[str, Any]) -> AlertType:
    """Determine the alert type based on keywords in the payload."""
    text_blob = _flatten_to_text(data).lower()
    
    for alert_type, keywords in ALERT_TYPE_KEYWORDS.items():
        for keyword in keywords:
            if keyword in text_blob:
                return alert_type
    
    return AlertType.UNKNOWN


def _normalize_timestamp(raw_timestamp: Any) -> datetime:
    """Parse various timestamp formats into a standard datetime.
    
    Supports:
    - ISO 8601 strings
    - Unix epoch (int/float)
    - Common date formats (MM/DD/YYYY, etc.)
    """
    if raw_timestamp is None:
        return datetime.utcnow()
    
    # Unix epoch timestamp
    if isinstance(raw_timestamp, (int, float)):
        try:
            return datetime.utcfromtimestamp(raw_timestamp)
        except (ValueError, OSError):
            return datetime.utcnow()
    
    # String timestamp — use dateutil for flexible parsing
    if isinstance(raw_timestamp, str):
        try:
            return date_parser.parse(raw_timestamp)
        except (ValueError, TypeError):
            logger.warning(f"Failed to parse timestamp: {raw_timestamp}")
            return datetime.utcnow()
    
    return datetime.utcnow()


def _normalize_severity(raw_severity: Any, source: SIEMSource) -> AlertSeverity:
    """Map SIEM-specific severity to our unified scale."""
    if raw_severity is None:
        return AlertSeverity.MEDIUM
    
    if source == SIEMSource.SPLUNK:
        return SPLUNK_SEVERITY_MAP.get(
            str(raw_severity).lower(), AlertSeverity.MEDIUM
        )
    elif source == SIEMSource.ELASTIC:
        return ELASTIC_SEVERITY_MAP.get(
            raw_severity if isinstance(raw_severity, int) else str(raw_severity).lower(),
            AlertSeverity.MEDIUM,
        )
    else:
        # Generic: try to match by string
        severity_str = str(raw_severity).lower()
        for key, value in SPLUNK_SEVERITY_MAP.items():
            if key in severity_str:
                return value
        return AlertSeverity.MEDIUM


def _detect_siem_source(payload: dict[str, Any], source_hint: Optional[str] = None) -> SIEMSource:
    """Detect which SIEM generated this alert based on payload structure."""
    if source_hint:
        hint_lower = source_hint.lower()
        if "splunk" in hint_lower:
            return SIEMSource.SPLUNK
        elif "elastic" in hint_lower:
            return SIEMSource.ELASTIC
    
    # Auto-detect by payload structure
    if "result" in payload and "_raw" in payload.get("result", {}):
        return SIEMSource.SPLUNK
    if "kibana" in str(payload) or "_source" in payload:
        return SIEMSource.ELASTIC
    
    return SIEMSource.GENERIC


def _extract_field(payload: dict[str, Any], *field_names: str, default: Any = None) -> Any:
    """Extract a value from payload trying multiple possible field names.
    
    Different SIEMs use different field names for the same concept.
    This function tries each name in order and returns the first match.
    """
    for name in field_names:
        # Try direct key
        if name in payload:
            return payload[name]
        # Try nested (e.g., "result.src_ip")
        parts = name.split(".")
        value = payload
        for part in parts:
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                value = None
                break
        if value is not None:
            return value
    return default


def normalize_alert(source: str, payload: dict[str, Any]) -> NormalizedAlert:
    """Normalize a raw SIEM alert into the standardized schema.
    
    This is the main entry point for the normalization pipeline.
    It detects the SIEM source, extracts relevant fields, normalizes
    timestamps and severity, and extracts IoCs.
    
    Args:
        source: SIEM source identifier hint (e.g., 'splunk', 'elastic', 'generic').
        payload: The raw alert JSON payload.
        
    Returns:
        A fully normalized NormalizedAlert object ready for enrichment.
    """
    logger.info(f"Normalizing alert from source: {source}")
    
    # Detect SIEM source
    siem_source = _detect_siem_source(payload, source)
    
    # Extract fields using multiple possible names
    raw_timestamp = _extract_field(
        payload,
        "timestamp", "@timestamp", "event_time", "_time",
        "created_at", "time", "date",
    )
    
    raw_severity = _extract_field(
        payload,
        "severity", "priority", "urgency", "risk_level",
        "alert_severity", "level",
    )
    
    source_ip = _extract_field(
        payload,
        "source_ip", "src_ip", "src", "attacker_ip",
        "remote_ip", "client_ip", "ip",
    )
    
    dest_ip = _extract_field(
        payload,
        "dest_ip", "dst_ip", "dst", "target_ip",
        "destination_ip", "server_ip",
    )
    
    target_host = _extract_field(
        payload,
        "target", "target_host", "hostname", "host",
        "instance_id", "device", "asset",
    )
    
    description = _extract_field(
        payload,
        "description", "message", "msg", "alert_description",
        "summary", "details", "reason",
        default="No description provided",
    )
    
    alert_type_raw = _extract_field(
        payload,
        "alert_type", "type", "event_type", "rule_name",
        "category", "action",
    )
    
    # Normalize timestamp
    timestamp = _normalize_timestamp(raw_timestamp)
    
    # Normalize severity
    severity = _normalize_severity(raw_severity, siem_source)
    
    # Classify alert type
    if alert_type_raw:
        # Try to match raw alert type to our enum
        try:
            alert_type = AlertType(alert_type_raw.lower())
        except ValueError:
            alert_type = _classify_alert_type(payload)
    else:
        alert_type = _classify_alert_type(payload)
    
    # Extract IoCs
    iocs = extract_iocs(payload)
    
    # If source_ip was found and not already in IoCs, add it
    if source_ip and not any(ioc.value == source_ip for ioc in iocs):
        if not _is_private_ip(source_ip):
            iocs.insert(0, IoC(
                ioc_type="ip",
                value=source_ip,
                context="Source IP from alert metadata",
            ))
    
    # Build the normalized alert
    normalized = NormalizedAlert(
        timestamp=timestamp,
        alert_type=alert_type,
        severity=severity,
        status=AlertStatus.NORMALIZED,
        source_ip=source_ip,
        dest_ip=dest_ip,
        target_host=target_host,
        description=str(description),
        iocs=iocs,
        siem_source=siem_source,
        raw_payload=payload,
    )
    
    logger.info(
        f"Alert normalized: {normalized.alert_id} | "
        f"Type: {normalized.alert_type} | "
        f"Severity: {normalized.severity} | "
        f"IoCs: {len(normalized.iocs)}"
    )
    
    return normalized
