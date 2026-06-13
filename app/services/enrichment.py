"""SOAR Engine - Threat Intelligence Enrichment Service

Provides automated threat enrichment by querying external APIs:
- AbuseIPDB: IP address reputation and abuse history
- VirusTotal: File hash malware analysis

Supports two modes:
- LIVE MODE: queries real APIs (requires valid API keys)
- SIMULATION MODE: returns realistic fake responses (for development/testing)

Includes in-memory caching to respect API rate limits and improve performance.
"""

import logging
import random
import time
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from app.config import settings
from app.models.alert import NormalizedAlert
from app.models.enrichment import (
    IPReputation,
    FileHashResult,
    EnrichmentResult,
)

logger = logging.getLogger(__name__)


# ── In-Memory Enrichment Cache ────────────────────────
# Avoids calling the same API endpoint twice for the same IP/hash.
# Key = IP or hash string, Value = (timestamp, result)
_ip_cache: dict[str, tuple[float, IPReputation]] = {}
_hash_cache: dict[str, tuple[float, FileHashResult]] = {}


def _is_cache_valid(cached_time: float) -> bool:
    """Check if a cached entry is still within the TTL window."""
    return (time.time() - cached_time) < settings.ENRICHMENT_CACHE_TTL


# ── AbuseIPDB Client ─────────────────────────────────

class AbuseIPDBClient:
    """Client for querying the AbuseIPDB CHECK endpoint.

    AbuseIPDB is a community-driven IP blacklist. The CHECK endpoint
    returns an abuse confidence score (0-100), country, ISP, and
    the number of times the IP has been reported.

    API Docs: https://docs.abuseipdb.com/#check-endpoint
    Free tier: 1,000 checks/day
    """

    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self):
        self.api_key = settings.ABUSEIPDB_API_KEY
        self.max_age_days = settings.ABUSEIPDB_MAX_AGE_DAYS

    def check_ip(self, ip_address: str) -> IPReputation:
        """Look up an IP address in AbuseIPDB.

        Args:
            ip_address: The IPv4 address to check (e.g., "103.24.55.12").

        Returns:
            IPReputation with abuse score, country, ISP, and report count.
        """
        # Check cache first
        if ip_address in _ip_cache:
            cached_time, cached_result = _ip_cache[ip_address]
            if _is_cache_valid(cached_time):
                logger.debug(f"AbuseIPDB cache hit for {ip_address}")
                return cached_result

        # Use simulation mode if enabled or API key is missing
        if settings.SIMULATION_MODE or not self.api_key:
            result = self._simulate_response(ip_address)
        else:
            result = self._call_api(ip_address)

        # Store in cache
        _ip_cache[ip_address] = (time.time(), result)
        return result

    def _call_api(self, ip_address: str) -> IPReputation:
        """Make a real HTTP request to the AbuseIPDB API."""
        try:
            response = httpx.get(
                self.BASE_URL,
                headers={
                    "Key": self.api_key,
                    "Accept": "application/json",
                },
                params={
                    "ipAddress": ip_address,
                    "maxAgeInDays": str(self.max_age_days),
                    "verbose": "",
                },
                timeout=10.0,
            )

            # Handle HTTP errors
            if response.status_code == 429:
                logger.warning(f"AbuseIPDB rate limit reached for {ip_address}")
                return self._simulate_response(ip_address)
            elif response.status_code == 401:
                logger.error("AbuseIPDB API key is invalid")
                return self._simulate_response(ip_address)
            elif response.status_code != 200:
                logger.error(f"AbuseIPDB returned status {response.status_code}")
                return self._simulate_response(ip_address)

            data = response.json().get("data", {})
            last_reported = None
            if data.get("lastReportedAt"):
                try:
                    last_reported = datetime.fromisoformat(
                        data["lastReportedAt"].replace("Z", "+00:00")
                    )
                except (ValueError, TypeError):
                    last_reported = None

            result = IPReputation(
                ip_address=ip_address,
                abuse_confidence_score=data.get("abuseConfidenceScore", 0),
                country_code=data.get("countryCode"),
                isp=data.get("isp"),
                domain=data.get("domain"),
                total_reports=data.get("totalReports", 0),
                last_reported_at=last_reported,
                is_whitelisted=data.get("isWhitelisted", False),
                is_tor=data.get("isTor", False),
                source="abuseipdb",
                raw_response=data,
            )

            logger.info(
                f"AbuseIPDB result for {ip_address}: "
                f"score={result.abuse_confidence_score}, "
                f"country={result.country_code}, "
                f"reports={result.total_reports}"
            )
            return result

        except httpx.ConnectError:
            logger.error(f"AbuseIPDB connection failed for {ip_address}")
            return self._simulate_response(ip_address)
        except httpx.TimeoutException:
            logger.error(f"AbuseIPDB request timed out for {ip_address}")
            return self._simulate_response(ip_address)
        except Exception as e:
            logger.error(f"AbuseIPDB unexpected error for {ip_address}: {e}")
            return self._simulate_response(ip_address)

    def _simulate_response(self, ip_address: str) -> IPReputation:
        """Generate a realistic simulated AbuseIPDB response.

        Produces varied scores so the risk scoring engine has diverse
        data to work with during development and testing.
        """
        # Seed based on IP to get consistent results for the same IP
        seed = sum(int(x) for x in ip_address.split(".") if x.isdigit())
        rng = random.Random(seed)

        # Most external IPs in our test data are "malicious"
        score = rng.choice([0, 5, 15, 25, 45, 65, 78, 85, 92, 97, 100])
        countries = ["US", "RU", "CN", "KP", "BR", "IN", "DE", "NL", "RO", "UA"]
        isps = [
            "Digital Ocean", "OVH SAS", "Hetzner", "Amazon AWS",
            "Alibaba Cloud", "Linode", "Vultr", "HostGator",
        ]

        result = IPReputation(
            ip_address=ip_address,
            abuse_confidence_score=score,
            country_code=rng.choice(countries),
            isp=rng.choice(isps),
            domain=f"host-{seed}.example.net",
            total_reports=rng.randint(0, 500) if score > 30 else rng.randint(0, 5),
            last_reported_at=datetime.now(timezone.utc) if score > 30 else None,
            is_whitelisted=False,
            is_tor=rng.random() < 0.1,
            source="abuseipdb_simulated",
            raw_response={"simulated": True},
        )

        logger.info(
            f"AbuseIPDB [SIMULATED] for {ip_address}: "
            f"score={result.abuse_confidence_score}, "
            f"country={result.country_code}"
        )
        return result


# ── VirusTotal Client ─────────────────────────────────

class VirusTotalClient:
    """Client for querying the VirusTotal file report endpoint.

    VirusTotal scans files against 70+ antivirus engines and returns
    detection statistics. We use it to check if file hashes found in
    alerts are known malware.

    API Docs: https://docs.virustotal.com/reference/file-info
    Free tier: 500 lookups/day, 4 lookups/minute
    """

    BASE_URL = "https://www.virustotal.com/api/v3/files"

    def __init__(self):
        self.api_key = settings.VIRUSTOTAL_API_KEY

    def check_hash(self, file_hash: str) -> FileHashResult:
        """Look up a file hash in VirusTotal.

        Args:
            file_hash: SHA-256, SHA-1, or MD5 hash string.

        Returns:
            FileHashResult with detection ratio, malware family, and dates.
        """
        # Determine hash type from length
        hash_type = "sha256"
        if len(file_hash) == 32:
            hash_type = "md5"
        elif len(file_hash) == 40:
            hash_type = "sha1"

        # Check cache first
        if file_hash in _hash_cache:
            cached_time, cached_result = _hash_cache[file_hash]
            if _is_cache_valid(cached_time):
                logger.debug(f"VirusTotal cache hit for {file_hash[:16]}...")
                return cached_result

        # Use simulation mode if enabled or API key is missing
        if settings.SIMULATION_MODE or not self.api_key:
            result = self._simulate_response(file_hash, hash_type)
        else:
            result = self._call_api(file_hash, hash_type)

        # Store in cache
        _hash_cache[file_hash] = (time.time(), result)
        return result

    def _call_api(self, file_hash: str, hash_type: str) -> FileHashResult:
        """Make a real HTTP request to the VirusTotal API."""
        try:
            response = httpx.get(
                f"{self.BASE_URL}/{file_hash}",
                headers={
                    "x-apikey": self.api_key,
                    "Accept": "application/json",
                },
                timeout=15.0,
            )

            # Handle HTTP errors
            if response.status_code == 429:
                logger.warning(f"VirusTotal rate limit reached for {file_hash[:16]}...")
                return self._simulate_response(file_hash, hash_type)
            elif response.status_code == 404:
                logger.info(f"VirusTotal: hash not found {file_hash[:16]}...")
                return FileHashResult(
                    file_hash=file_hash,
                    hash_type=hash_type,
                    is_malicious=False,
                    source="virustotal",
                    raw_response={"not_found": True},
                )
            elif response.status_code == 401:
                logger.error("VirusTotal API key is invalid")
                return self._simulate_response(file_hash, hash_type)
            elif response.status_code != 200:
                logger.error(f"VirusTotal returned status {response.status_code}")
                return self._simulate_response(file_hash, hash_type)

            data = response.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            malicious_count = stats.get("malicious", 0)
            total_engines = sum(stats.values()) if stats else 0
            detection_ratio = f"{malicious_count}/{total_engines}" if total_engines else None

            # Try to get malware family from popular threat labels
            malware_family = None
            popular = attrs.get("popular_threat_classification", {})
            if popular.get("suggested_threat_label"):
                malware_family = popular["suggested_threat_label"]

            first_seen = None
            if attrs.get("first_submission_date"):
                try:
                    first_seen = datetime.fromtimestamp(
                        attrs["first_submission_date"], tz=timezone.utc
                    )
                except (ValueError, OSError):
                    pass

            last_seen = None
            if attrs.get("last_analysis_date"):
                try:
                    last_seen = datetime.fromtimestamp(
                        attrs["last_analysis_date"], tz=timezone.utc
                    )
                except (ValueError, OSError):
                    pass

            result = FileHashResult(
                file_hash=file_hash,
                hash_type=hash_type,
                detection_ratio=detection_ratio,
                malware_family=malware_family,
                first_seen=first_seen,
                last_seen=last_seen,
                is_malicious=malicious_count > 5,
                source="virustotal",
                raw_response={"stats": stats},
            )

            logger.info(
                f"VirusTotal result for {file_hash[:16]}...: "
                f"detection={detection_ratio}, "
                f"malicious={result.is_malicious}"
            )
            return result

        except httpx.ConnectError:
            logger.error(f"VirusTotal connection failed for {file_hash[:16]}...")
            return self._simulate_response(file_hash, hash_type)
        except httpx.TimeoutException:
            logger.error(f"VirusTotal request timed out for {file_hash[:16]}...")
            return self._simulate_response(file_hash, hash_type)
        except Exception as e:
            logger.error(f"VirusTotal unexpected error: {e}")
            return self._simulate_response(file_hash, hash_type)

    def _simulate_response(self, file_hash: str, hash_type: str) -> FileHashResult:
        """Generate a realistic simulated VirusTotal response."""
        seed = sum(ord(c) for c in file_hash[:16])
        rng = random.Random(seed)

        is_malicious = rng.random() < 0.6  # 60% chance of being malicious in test data
        if is_malicious:
            malicious_count = rng.randint(15, 62)
            families = ["Emotet", "TrickBot", "Cobalt Strike", "Mimikatz",
                        "WannaCry", "Agent Tesla", "Remcos RAT", "RedLine"]
            malware_family = rng.choice(families)
        else:
            malicious_count = rng.randint(0, 3)
            malware_family = None

        total_engines = 72
        detection_ratio = f"{malicious_count}/{total_engines}"

        result = FileHashResult(
            file_hash=file_hash,
            hash_type=hash_type,
            detection_ratio=detection_ratio,
            malware_family=malware_family,
            first_seen=datetime(2024, rng.randint(1, 12), rng.randint(1, 28), tzinfo=timezone.utc),
            last_seen=datetime.now(timezone.utc),
            is_malicious=is_malicious,
            source="virustotal_simulated",
            raw_response={"simulated": True, "stats": {"malicious": malicious_count}},
        )

        logger.info(
            f"VirusTotal [SIMULATED] for {file_hash[:16]}...: "
            f"detection={detection_ratio}, "
            f"malware={malware_family or 'clean'}"
        )
        return result


# ── Enrichment Service (Orchestrates Everything) ─────

class EnrichmentService:
    """Orchestrates threat intelligence enrichment for alerts.

    Takes a NormalizedAlert, extracts its IoCs, queries the relevant
    threat intelligence APIs, and returns a combined EnrichmentResult.

    Usage:
        service = EnrichmentService()
        result = service.enrich(alert)
        # result.ip_results → list of AbuseIPDB lookups
        # result.hash_results → list of VirusTotal lookups
        # result.overall_threat_level → "low" / "medium" / "high" / "critical"
    """

    def __init__(self):
        self.abuseipdb = AbuseIPDBClient()
        self.virustotal = VirusTotalClient()

    def enrich(self, alert: NormalizedAlert) -> EnrichmentResult:
        """Enrich an alert by querying threat intelligence for all its IoCs.

        Args:
            alert: The normalized alert containing IoCs to look up.

        Returns:
            EnrichmentResult with all IP and hash lookup results.
        """
        if not settings.ENRICHMENT_ENABLED:
            logger.info(f"Enrichment disabled, skipping alert {alert.alert_id}")
            return EnrichmentResult(alert_id=alert.alert_id)

        logger.info(f"Enriching alert {alert.alert_id} with {len(alert.iocs)} IoCs")

        ip_results = []
        hash_results = []
        notes = []

        for ioc in alert.iocs:
            if ioc.ioc_type == "ip":
                result = self.abuseipdb.check_ip(ioc.value)
                ip_results.append(result)

                if result.abuse_confidence_score >= 80:
                    notes.append(
                        f"HIGH RISK IP: {ioc.value} has abuse score "
                        f"{result.abuse_confidence_score}/100 "
                        f"({result.country_code}, {result.isp})"
                    )

            elif ioc.ioc_type in ("hash_sha256", "hash_sha1", "hash_md5"):
                result = self.virustotal.check_hash(ioc.value)
                hash_results.append(result)

                if result.is_malicious:
                    notes.append(
                        f"MALWARE DETECTED: {ioc.value[:16]}... identified as "
                        f"{result.malware_family or 'unknown malware'} "
                        f"(detection: {result.detection_ratio})"
                    )

        # Calculate overall threat level based on enrichment results
        threat_level = self._calculate_threat_level(ip_results, hash_results)
        confidence = self._calculate_confidence(ip_results, hash_results)

        enrichment = EnrichmentResult(
            alert_id=alert.alert_id,
            enriched_at=datetime.now(timezone.utc),
            ip_results=ip_results,
            hash_results=hash_results,
            overall_threat_level=threat_level,
            confidence=confidence,
            notes=notes,
        )

        logger.info(
            f"Alert {alert.alert_id} enriched: "
            f"threat_level={threat_level}, "
            f"confidence={confidence:.2f}, "
            f"ip_lookups={len(ip_results)}, "
            f"hash_lookups={len(hash_results)}"
        )

        return enrichment

    def _calculate_threat_level(
        self,
        ip_results: list[IPReputation],
        hash_results: list[FileHashResult],
    ) -> str:
        """Determine overall threat level from enrichment data.

        Uses the worst-case indicator — if any single IoC is highly
        malicious, the whole alert gets a high threat level.
        """
        max_ip_score = 0
        if ip_results:
            max_ip_score = max(r.abuse_confidence_score for r in ip_results)

        has_malware = any(r.is_malicious for r in hash_results)

        # Decision logic
        if has_malware or max_ip_score >= 90:
            return "critical"
        elif max_ip_score >= 70:
            return "high"
        elif max_ip_score >= 40:
            return "medium"
        elif max_ip_score >= 10:
            return "low"
        else:
            return "unknown"

    def _calculate_confidence(
        self,
        ip_results: list[IPReputation],
        hash_results: list[FileHashResult],
    ) -> float:
        """Calculate confidence in the enrichment results (0.0 to 1.0).

        Higher confidence when we have more data points and consistent signals.
        """
        if not ip_results and not hash_results:
            return 0.0

        data_points = len(ip_results) + len(hash_results)
        # Base confidence from having data
        confidence = min(data_points * 0.15, 0.6)

        # Boost if multiple sources agree
        if ip_results and hash_results:
            confidence += 0.2

        # Boost from high-confidence individual results
        if ip_results:
            avg_score = sum(r.abuse_confidence_score for r in ip_results) / len(ip_results)
            if avg_score > 70:
                confidence += 0.15

        if any(r.is_malicious for r in hash_results):
            confidence += 0.1

        return min(round(confidence, 2), 1.0)


# ── Cache Management ─────────────────────────────────

def clear_enrichment_cache():
    """Clear all cached enrichment results."""
    _ip_cache.clear()
    _hash_cache.clear()
    logger.info("Enrichment cache cleared")


def get_cache_stats() -> dict[str, int]:
    """Return current cache statistics."""
    return {
        "ip_cache_size": len(_ip_cache),
        "hash_cache_size": len(_hash_cache),
        "total_cached": len(_ip_cache) + len(_hash_cache),
    }
