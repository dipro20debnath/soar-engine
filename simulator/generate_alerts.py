"""
SIEM Alert Simulator
====================

Generates realistic simulated SIEM alerts and sends them to the SOAR engine
via the webhook endpoint (POST /api/alerts).

Supports multiple SIEM formats (Splunk, Elastic, Generic) and attack scenarios
(brute force, malware, suspicious login, port scan).

Usage:
    # Send 10 random alerts with 1-second delay between each:
    python -m simulator.generate_alerts

    # Send 5 brute force alerts:
    python -m simulator.generate_alerts --type brute_force --count 5

    # Send alerts in Splunk format:
    python -m simulator.generate_alerts --siem splunk --count 3
"""

import argparse
import json
import random
import sys
import time
from datetime import datetime, timedelta

import httpx

# ── Configuration ──────────────────────────────────────
SOAR_URL = "http://localhost:8000/api/alerts"
SOAR_BULK_URL = "http://localhost:8000/api/alerts/bulk"

# ── Realistic Fake Data ────────────────────────────────

# Known malicious IPs (for simulation)
MALICIOUS_IPS = [
    "103.24.55.12", "185.220.101.45", "45.33.32.156",
    "198.51.100.23", "203.0.113.42", "91.198.174.192",
    "77.88.55.66", "123.45.67.89", "210.150.100.50",
    "185.143.223.12", "46.166.182.100", "31.13.64.35",
]

# Internal server IPs / hostnames
INTERNAL_TARGETS = [
    {"ip": "10.0.1.50", "host": "web-server-01", "instance": "i-0abc123def"},
    {"ip": "10.0.1.51", "host": "api-server-02", "instance": "i-0def456ghi"},
    {"ip": "10.0.2.10", "host": "db-primary-01", "instance": "i-0ghi789jkl"},
    {"ip": "10.0.2.11", "host": "db-replica-01", "instance": "i-0jkl012mno"},
    {"ip": "10.0.3.20", "host": "file-server-01", "instance": "i-0mno345pqr"},
    {"ip": "10.0.3.30", "host": "mail-server-01", "instance": "i-0pqr678stu"},
]

# Fake file hashes (simulated malware samples)
MALWARE_HASHES = [
    "e99a18c428cb38d5f260853678922e03abd833b3ba0f0b4e2b56b6e5c4b0e7a1",
    "d41d8cd98f00b204e9800998ecf8427e523456789abcdef0123456789abcdef01",
    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
    "5d41402abc4b2a76b9719d911017c592de45e7a3b4c5d6e7f8a9b0c1d2e3f4a5",
]

# Suspicious URLs
SUSPICIOUS_URLS = [
    "http://malware-c2.evil.com/beacon",
    "https://phishing-site.xyz/login.php",
    "http://103.24.55.12:8080/download/payload.exe",
]

# User accounts
USERS = [
    "admin", "jsmith", "arahman", "pkumar",
    "smanager", "dbadmin", "root", "service_account",
]

# Geo locations (for suspicious login scenarios)
GEO_LOCATIONS = [
    {"country": "BD", "city": "Dhaka"},
    {"country": "US", "city": "New York"},
    {"country": "RU", "city": "Moscow"},
    {"country": "CN", "city": "Beijing"},
    {"country": "KP", "city": "Pyongyang"},
    {"country": "IN", "city": "Mumbai"},
]


# ── Alert Generators ──────────────────────────────────

def generate_brute_force_alert(siem_format: str = "generic") -> dict:
    """Generate a simulated brute-force attack alert."""
    source_ip = random.choice(MALICIOUS_IPS)
    target = random.choice(INTERNAL_TARGETS)
    user = random.choice(USERS)
    failed_attempts = random.randint(10, 500)
    timestamp = (datetime.utcnow() - timedelta(minutes=random.randint(0, 30))).isoformat()

    if siem_format == "splunk":
        return {
            "source": "splunk",
            "payload": {
                "result": {
                    "_time": timestamp,
                    "src_ip": source_ip,
                    "dest": target["host"],
                    "user": user,
                    "action": "failure",
                    "app": "sshd",
                    "_raw": f"Failed password for {user} from {source_ip} port 22 ssh2 ({failed_attempts} attempts)",
                },
                "search_name": "Brute Force Detection Rule",
                "severity": random.choice(["high", "critical"]),
                "alert_type": "brute_force",
            },
        }
    elif siem_format == "elastic":
        return {
            "source": "elastic",
            "payload": {
                "@timestamp": timestamp,
                "_source": {
                    "source.ip": source_ip,
                    "destination.ip": target["ip"],
                    "host.name": target["host"],
                    "user.name": user,
                    "event.category": "authentication",
                    "event.outcome": "failure",
                    "event.count": failed_attempts,
                },
                "rule": {"name": "Brute Force Attack Detected"},
                "severity": random.choice([4, 5]),
                "alert_type": "brute_force",
                "message": f"Multiple failed login attempts ({failed_attempts}) from {source_ip} targeting {user}@{target['host']}",
            },
        }
    else:
        return {
            "source": "generic",
            "payload": {
                "timestamp": timestamp,
                "alert_type": "brute_force",
                "severity": random.choice(["high", "critical"]),
                "source_ip": source_ip,
                "dest_ip": target["ip"],
                "target": target["host"],
                "description": f"Brute force attack detected: {failed_attempts} failed login attempts for user '{user}' from {source_ip}",
                "details": {
                    "username": user,
                    "failed_attempts": failed_attempts,
                    "service": "SSH",
                    "port": 22,
                },
            },
        }


def generate_malware_alert(siem_format: str = "generic") -> dict:
    """Generate a simulated malware detection alert."""
    source_ip = random.choice(MALICIOUS_IPS)
    target = random.choice(INTERNAL_TARGETS)
    file_hash = random.choice(MALWARE_HASHES)
    timestamp = (datetime.utcnow() - timedelta(minutes=random.randint(0, 15))).isoformat()
    malware_names = ["Emotet", "TrickBot", "Cobalt Strike", "Mimikatz", "WannaCry"]

    if siem_format == "splunk":
        return {
            "source": "splunk",
            "payload": {
                "result": {
                    "_time": timestamp,
                    "src_ip": source_ip,
                    "dest": target["host"],
                    "file_hash": file_hash,
                    "file_name": "update.exe",
                    "_raw": f"Malware detected on {target['host']}: {random.choice(malware_names)} (hash: {file_hash})",
                },
                "severity": "critical",
                "alert_type": "malware_detected",
            },
        }
    elif siem_format == "elastic":
        return {
            "source": "elastic",
            "payload": {
                "@timestamp": timestamp,
                "_source": {
                    "source.ip": source_ip,
                    "host.name": target["host"],
                    "file.hash.sha256": file_hash,
                    "file.name": "update.exe",
                    "event.category": "malware",
                },
                "rule": {"name": "Malware Detection Alert"},
                "severity": 5,
                "alert_type": "malware_detected",
                "message": f"Malware {random.choice(malware_names)} detected on {target['host']}",
            },
        }
    else:
        malware_name = random.choice(malware_names)
        return {
            "source": "generic",
            "payload": {
                "timestamp": timestamp,
                "alert_type": "malware_detected",
                "severity": "critical",
                "source_ip": source_ip,
                "target": target["host"],
                "description": f"Malware detected: {malware_name} found on {target['host']}",
                "details": {
                    "malware_family": malware_name,
                    "file_name": "update.exe",
                    "file_hash_sha256": file_hash,
                    "file_path": f"/tmp/{random.choice(['update.exe', 'svchost.exe', 'payload.dll'])}",
                    "c2_url": random.choice(SUSPICIOUS_URLS),
                },
            },
        }


def generate_suspicious_login_alert(siem_format: str = "generic") -> dict:
    """Generate a simulated suspicious login alert (geo anomaly / impossible travel)."""
    source_ip = random.choice(MALICIOUS_IPS)
    target = random.choice(INTERNAL_TARGETS)
    user = random.choice(USERS)
    geo = random.choice(GEO_LOCATIONS)
    timestamp = (datetime.utcnow() - timedelta(minutes=random.randint(0, 60))).isoformat()

    if siem_format == "splunk":
        return {
            "source": "splunk",
            "payload": {
                "result": {
                    "_time": timestamp,
                    "src_ip": source_ip,
                    "user": user,
                    "dest": target["host"],
                    "_raw": f"Suspicious login: {user} logged in from {geo['city']}, {geo['country']} ({source_ip})",
                },
                "severity": "high",
                "alert_type": "suspicious_login",
            },
        }
    elif siem_format == "elastic":
        return {
            "source": "elastic",
            "payload": {
                "@timestamp": timestamp,
                "_source": {
                    "source.ip": source_ip,
                    "source.geo.country_iso_code": geo["country"],
                    "source.geo.city_name": geo["city"],
                    "user.name": user,
                    "host.name": target["host"],
                    "event.category": "authentication",
                    "event.outcome": "success",
                },
                "rule": {"name": "Impossible Travel Detection"},
                "severity": 4,
                "alert_type": "suspicious_login",
                "message": f"Suspicious login: {user} from {geo['city']}, {geo['country']}",
            },
        }
    else:
        return {
            "source": "generic",
            "payload": {
                "timestamp": timestamp,
                "alert_type": "suspicious_login",
                "severity": "high",
                "source_ip": source_ip,
                "target": target["host"],
                "description": f"Suspicious login detected: User '{user}' logged in from {geo['city']}, {geo['country']} ({source_ip})",
                "details": {
                    "username": user,
                    "geo_country": geo["country"],
                    "geo_city": geo["city"],
                    "login_type": "VPN",
                    "previous_location": "Dhaka, BD",
                    "time_since_last_login": "2 hours",
                },
            },
        }


def generate_port_scan_alert(siem_format: str = "generic") -> dict:
    """Generate a simulated port scan / reconnaissance alert."""
    source_ip = random.choice(MALICIOUS_IPS)
    target = random.choice(INTERNAL_TARGETS)
    ports_scanned = random.randint(100, 65535)
    timestamp = (datetime.utcnow() - timedelta(minutes=random.randint(0, 10))).isoformat()

    return {
        "source": siem_format,
        "payload": {
            "timestamp": timestamp,
            "alert_type": "port_scan",
            "severity": "medium",
            "source_ip": source_ip,
            "dest_ip": target["ip"],
            "target": target["host"],
            "description": f"Port scan detected: {source_ip} scanned {ports_scanned} ports on {target['host']}",
            "details": {
                "ports_scanned": ports_scanned,
                "scan_type": random.choice(["SYN", "TCP Connect", "UDP", "FIN"]),
                "duration_seconds": random.randint(10, 300),
                "open_ports_found": random.sample([22, 80, 443, 3306, 5432, 8080, 8443], k=random.randint(1, 4)),
            },
        },
    }


# ── Alert Generator Registry ──────────────────────────
GENERATORS = {
    "brute_force": generate_brute_force_alert,
    "malware_detected": generate_malware_alert,
    "suspicious_login": generate_suspicious_login_alert,
    "port_scan": generate_port_scan_alert,
}


def generate_random_alert(siem_format: str = "generic") -> dict:
    """Generate a random alert of any type."""
    generator = random.choice(list(GENERATORS.values()))
    return generator(siem_format)


def send_alert(alert_data: dict, base_url: str = SOAR_URL) -> dict:
    """Send a single alert to the SOAR engine webhook endpoint."""
    try:
        response = httpx.post(
            base_url,
            json=alert_data,
            timeout=10.0,
        )
        response.raise_for_status()
        return response.json()
    except httpx.ConnectError:
        print(f"  [ERROR] Connection failed! Is the SOAR server running at {base_url}?")
        print(f"     Start it with: uvicorn app.main:app --reload")
        return {"error": "connection_failed"}
    except Exception as e:
        print(f"  [ERROR] Error: {e}")
        return {"error": str(e)}


def main():
    """Main entry point for the SIEM simulator."""
    parser = argparse.ArgumentParser(
        description="SIEM Alert Simulator — Generates fake security alerts for SOAR testing",
    )
    parser.add_argument(
        "--type", "-t",
        choices=list(GENERATORS.keys()) + ["random"],
        default="random",
        help="Type of alert to generate (default: random)",
    )
    parser.add_argument(
        "--count", "-c",
        type=int,
        default=10,
        help="Number of alerts to send (default: 10)",
    )
    parser.add_argument(
        "--delay", "-d",
        type=float,
        default=1.0,
        help="Delay between alerts in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--siem", "-s",
        choices=["generic", "splunk", "elastic", "mixed"],
        default="mixed",
        help="SIEM format to simulate (default: mixed)",
    )
    parser.add_argument(
        "--url", "-u",
        default=SOAR_URL,
        help=f"SOAR webhook URL (default: {SOAR_URL})",
    )

    args = parser.parse_args()

    print("=" * 60)
    print("  [*] SIEM Alert Simulator")
    print(f"  Target:  {args.url}")
    print(f"  Type:    {args.type}")
    print(f"  Count:   {args.count}")
    print(f"  SIEM:    {args.siem}")
    print(f"  Delay:   {args.delay}s")
    print("=" * 60)
    print()

    success_count = 0
    fail_count = 0

    for i in range(args.count):
        # Choose SIEM format
        if args.siem == "mixed":
            siem_format = random.choice(["generic", "splunk", "elastic"])
        else:
            siem_format = args.siem

        # Generate alert
        if args.type == "random":
            alert_data = generate_random_alert(siem_format)
        else:
            generator = GENERATORS[args.type]
            alert_data = generator(siem_format)

        # Send alert
        print(f"  [{i + 1}/{args.count}] Sending {alert_data['payload'].get('alert_type', 'unknown')} alert ({siem_format} format)...")
        result = send_alert(alert_data, args.url)

        if "error" not in result:
            print(f"           [OK] Alert ID: {result.get('alert_id', 'N/A')} | "
                  f"Severity: {result.get('severity', 'N/A')} | "
                  f"IoCs: {result.get('ioc_count', 0)}")
            success_count += 1
        else:
            fail_count += 1
            if result["error"] == "connection_failed":
                print("  Stopping — server not reachable.")
                break

        # Delay between alerts
        if i < args.count - 1:
            time.sleep(args.delay)

    print()
    print("=" * 60)
    print(f"  [RESULTS] {success_count} sent, {fail_count} failed")
    print("=" * 60)


if __name__ == "__main__":
    main()
