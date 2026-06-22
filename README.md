# SOAR Incident Containment Engine

> Security Orchestration, Automation, and Response engine for automated threat detection, enrichment, and containment.

[![Python 3.13](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green.svg)](https://fastapi.tiangolo.com/)
[![Tests](https://img.shields.io/badge/tests-270%20passing-brightgreen.svg)](#testing)

## Overview

The SOAR Incident Containment Engine is a Python-based security automation platform that receives alerts from multiple SIEM systems, enriches them with threat intelligence, calculates risk scores, and automatically executes response playbooks to contain security incidents.

### Full Pipeline

```
Raw SIEM Alert → Normalize → Enrich (AbuseIPDB + VirusTotal) → Risk Score → Playbook → Contain → Store
```

### Key Features

- **Multi-SIEM Support** — Ingests alerts from Splunk, Elastic SIEM, and generic JSON formats
- **IoC Extraction** — Automatically extracts IPs, file hashes, URLs, emails, and domains
- **Threat Intelligence** — Enriches IoCs via AbuseIPDB and VirusTotal APIs (with simulation mode)
- **Risk Scoring** — Weighted algorithm: IP reputation (40%) + Severity (30%) + IoC count (15%) + VT results (15%)
- **Response Playbooks** — 5 dedicated playbooks + 1 default, with enrichment-driven escalation
- **Automated Containment** — IP blocking, host isolation, file quarantine, account locking
- **Approval Workflow** — High-impact actions on critical alerts require human approval
- **SOC Dashboard** — Beautiful dark-themed dashboard with live charts, alerts table, and containment controls
- **SQLite Persistence** — Alerts and playbooks are persistently stored using SQLite
- **RESTful API** — 30+ endpoints with interactive Swagger docs

---

## Project Structure

```
soar-engine/
├── app/
│   ├── main.py                         # FastAPI application entry point
│   ├── config.py                       # Environment configuration
│   ├── models/
│   │   ├── alert.py                    # Alert data models (NormalizedAlert, IoC, enums)
│   │   └── enrichment.py              # Enrichment data models (IPReputation, FileHashResult)
│   ├── services/
│   │   ├── normalizer.py              # Multi-SIEM alert normalization
│   │   ├── enrichment.py              # Threat intelligence enrichment service
│   │   ├── risk_scorer.py             # Weighted risk scoring algorithm
│   │   └── playbook_engine.py         # Playbook execution engine
│   ├── playbooks/
│   │   ├── base.py                    # BasePlaybook abstract interface
│   │   ├── default.py                 # DefaultPlaybook (fallback)
│   │   ├── brute_force.py             # Brute force response
│   │   ├── malware_detected.py        # Malware detection response
│   │   ├── suspicious_login.py        # Suspicious login response
│   │   ├── port_scan.py               # Port scan response
│   │   └── data_exfiltration.py       # Data exfiltration response
│   ├── containment/
│   │   ├── firewall.py                # Simulated firewall (IP blocklist)
│   │   ├── aws_isolator.py            # Simulated AWS EC2 isolator
│   │   └── notification.py            # SOC notification service
│   ├── routers/
│   │   ├── webhooks.py                # POST /api/alerts — SIEM webhook receiver
│   │   ├── alerts.py                  # GET /api/alerts — Query & enrichment endpoints
│   │   └── playbooks.py              # Containment & approval workflow endpoints
│   └── db/
│       ├── store.py                   # Store factory (switches between memory/sqlite)
│       ├── sqlite_store.py            # SQLite persistent alert store
│       └── memory_store.py            # In-memory fallback alert store
├── dashboard/
│   ├── index.html                     # Dashboard UI
│   ├── style.css                      # SOC-themed CSS (glassmorphism)
│   └── app.js                         # Live API integration & Chart.js
├── tests/
│   ├── test_normalizer.py            # 27 normalization tests
│   ├── test_store.py                 # 14 alert store tests
│   ├── test_enrichment.py            # 20 enrichment tests
│   ├── test_risk_scorer.py           # 30 risk scoring tests
│   ├── test_playbook_engine.py       # 69 playbook & engine tests
│   ├── test_containment.py           # 38 containment & approval tests
│   ├── test_integration.py           # 44 end-to-end API tests
│   └── test_sqlite_store.py          # 28 SQLite persistence tests
├── simulator/
│   └── generate_alerts.py            # SIEM alert simulator for testing
├── requirements.txt
└── README.md
```

---

## Quick Start

### 1. Clone & Setup

```bash
git clone https://github.com/dipro20debnath/soar-engine.git
cd soar-engine
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux/Mac
pip install -r requirements.txt
```

### 2. Configure Environment

Create a `.env` file (optional — simulation mode works without API keys):

```env
# Simulation mode uses fake API responses (no API keys needed)
SIMULATION_MODE=true
ENRICHMENT_ENABLED=true
DEBUG=true

# Optional: Real API keys (set SIMULATION_MODE=false to use)
ABUSEIPDB_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
```

### 3. Run the Server

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 4. Open the Dashboards

- **SOC Dashboard**: Navigate to [http://localhost:8000/dashboard/](http://localhost:8000/dashboard/)
- **Swagger API Docs**: Navigate to [http://localhost:8000/docs](http://localhost:8000/docs)

### 5. Send a Test Alert

```bash
curl -X POST http://localhost:8000/api/alerts \
  -H "Content-Type: application/json" \
  -d '{
    "source": "generic",
    "payload": {
      "alert_type": "brute_force",
      "severity": "high",
      "source_ip": "185.220.101.45",
      "target_host": "web-server-01",
      "description": "50 failed SSH login attempts in 60 seconds"
    }
  }'
```

### 6. Run the SIEM Simulator

```bash
python -m simulator.generate_alerts --count 10
```

---

## API Endpoints

### Webhooks (Alert Ingestion)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/alerts` | Receive a single SIEM alert |
| `POST` | `/api/alerts/bulk` | Receive multiple alerts in batch |

### Alerts (Query & Management)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/alerts` | List alerts with filtering (severity, type, status) |
| `GET` | `/api/alerts/{id}` | Get full alert details |
| `DELETE` | `/api/alerts/{id}` | Delete an alert |
| `GET` | `/api/stats` | Aggregated alert statistics |

### Enrichment

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/enrich/{id}` | Manually trigger enrichment for an alert |
| `GET` | `/api/enrichment/cache` | View enrichment cache stats |
| `DELETE` | `/api/enrichment/cache` | Clear enrichment cache |

### Playbooks & Response

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/playbooks` | List all registered playbooks |
| `GET` | `/api/playbooks/history` | Playbook execution history |
| `GET` | `/api/playbooks/pending` | Alerts awaiting approval |
| `POST` | `/api/playbooks/approve/{id}` | Approve high-impact actions |
| `POST` | `/api/playbooks/reject/{id}` | Reject high-impact actions |

### Containment

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/containment/blocklist` | View blocked IPs |
| `POST` | `/api/containment/block/{ip}` | Manually block an IP |
| `POST` | `/api/containment/unblock/{ip}` | Unblock an IP |
| `GET` | `/api/containment/firewall/log` | Firewall action audit log |
| `GET` | `/api/containment/isolated` | View isolated instances |
| `POST` | `/api/containment/restore/{id}` | Restore isolated instance |
| `GET` | `/api/containment/notifications` | SOC notification history |
| `GET` | `/api/containment/summary` | Full containment overview |

### Health

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | System info & endpoint listing |
| `GET` | `/health` | Detailed health check |

---

## Response Playbooks

Each playbook uses **risk-tiered actions** and **enrichment-driven intelligence**:

| Playbook | Alert Type | Low Risk | Medium Risk | High Risk |
|----------|------------|----------|-------------|-----------|
| `brute_force_response` | Brute Force | Log only | Watchlist IP + notify | Block IP + critical alert |
| `malware_response` | Malware Detected | Log & monitor | Quarantine hash + notify | Isolate host + block C2 |
| `suspicious_login_response` | Suspicious Login | Log only | Force password reset | Lock account + block IP |
| `port_scan_response` | Port Scan | Log only | Rate-limit IP | Block IP + incident ticket |
| `data_exfiltration_response` | Data Exfiltration | Monitor traffic | Throttle outbound | Isolate host + block dest |
| `default_triage` | Unknown/Other | Log alert | Assign triage ticket | Escalate to senior analyst |

### Enrichment-Driven Escalation

Playbooks automatically escalate their response based on threat intelligence:

- **AbuseIPDB score ≥ 90** → Force high-risk tier (block IP)
- **Tor exit node detected** → Escalate to at least medium tier
- **Critical malware family** (Emotet, TrickBot, WannaCry, etc.) → Force host isolation
- **VirusTotal detection ratio > 50** → Escalate quarantine actions
- **C2 URLs in IoCs** → Force high-risk tier on data exfiltration

### Approval Workflow

When **risk score > 90** and actions include `isolate_host` or `lock_account`:
1. Non-destructive actions execute immediately
2. High-impact actions are **deferred** → alert status becomes `PENDING_APPROVAL`
3. Analyst reviews via `GET /api/playbooks/pending`
4. `POST /api/playbooks/approve/{id}` → executes deferred actions
5. `POST /api/playbooks/reject/{id}` → discards them

---

## Risk Scoring

The weighted risk scoring algorithm combines four factors:

| Factor | Weight | Source |
|--------|--------|--------|
| IP Reputation | 40% | AbuseIPDB confidence score |
| Alert Severity | 30% | Normalized severity level |
| IoC Count | 15% | Number of extracted indicators |
| VirusTotal | 15% | Malware detection ratio |

**Risk Levels:**
- 🟢 **Low** (0–30): Monitor only
- 🟡 **Medium** (31–60): Investigate
- 🟠 **High** (61–80): Containment recommended
- 🔴 **Critical** (81–100): Immediate action required

---

## Testing

Run the full test suite:

```bash
# All 270 tests
pytest tests/ -v

# By module
pytest tests/test_normalizer.py -v       # 27 normalization tests
pytest tests/test_store.py -v            # 14 alert store tests
pytest tests/test_enrichment.py -v       # 20 enrichment tests
pytest tests/test_risk_scorer.py -v      # 30 risk scoring tests
pytest tests/test_playbook_engine.py -v  # 69 playbook tests
pytest tests/test_containment.py -v      # 38 containment tests
pytest tests/test_integration.py -v      # 44 integration tests
pytest tests/test_sqlite_store.py -v     # 28 SQLite tests
```

---

## Technology Stack

- **Python 3.13** — Core language
- **FastAPI** — Async web framework with automatic OpenAPI docs
- **Pydantic** — Data validation and serialization
- **httpx** — HTTP client for API calls
- **pytest** — Testing framework
- **python-dotenv** — Environment variable management
- **uvicorn** — ASGI server

---

## Architecture

```
┌─────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  SIEM Alert  │───▶│  Normalizer  │───▶│  Enrichment  │───▶│ Risk Scorer  │
│  (Webhook)   │    │ (Multi-SIEM) │    │(AbuseIPDB+VT)│    │  (Weighted)  │
└─────────────┘    └──────────────┘    └──────────────┘    └──────┬───────┘
                                                                  │
                   ┌──────────────┐    ┌──────────────┐    ┌──────▼───────┐
                   │  Alert Store │◀───│ Containment  │◀───│   Playbook   │
                   │   (SQLite)   │    │ (FW/ISO/SOC) │    │   Engine     │
                   └──────────────┘    └──────────────┘    └──────────────┘
                                              │
                                       ┌──────▼───────┐
                                       │   Approval   │
                                       │  Workflow    │
                                       │ (risk > 90)  │
                                       └──────────────┘
```

---

## License

This project is developed as part of the Infotact internship program.

## Author

**Dipro Debnath** — [@dipro20debnath](https://github.com/dipro20debnath)
