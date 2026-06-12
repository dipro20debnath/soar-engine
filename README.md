# SOAR Incident Containment Engine

> **Security Orchestration, Automation, and Response (SOAR)** engine for automated threat detection, enrichment, and containment.

[![Python](https://img.shields.io/badge/Python-3.13-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green.svg)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Overview

This project builds a custom SOAR engine that:
1. **Receives** security alerts from SIEM systems via webhooks
2. **Normalizes** alerts from multiple SIEM formats (Splunk, Elastic, Generic) into a unified schema
3. **Extracts** Indicators of Compromise (IoCs) — IP addresses, file hashes, URLs, emails
4. **Enriches** alerts with threat intelligence (AbuseIPDB, VirusTotal) *(Week 2)*
5. **Executes** automated response playbooks based on risk scoring *(Week 3)*
6. **Visualizes** everything in a real-time SOC dashboard *(Week 4)*

## Architecture

```
SIEM Alert --> Webhook Receiver --> Normalizer --> IoC Extraction --> Enrichment --> Risk Scoring --> Playbook Engine --> Containment Actions
                                                                                                                            |
                                                                                              Dashboard <-- Database <------+
```

## Quick Start

### Prerequisites
- Python 3.10 or higher
- pip (Python package manager)

### Installation

```bash
# Clone the repository
git clone https://github.com/dipro20debnath/soar-engine.git
cd soar-engine

# Create virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Setup environment variables
copy .env.example .env
```

### Run the Server

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The server will start at `http://localhost:8000`

- **API Docs (Swagger)**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **Health Check**: http://localhost:8000/health

### Send Test Alerts

In a separate terminal:

```bash
# Send 10 random alerts from mixed SIEM formats
python -m simulator.generate_alerts

# Send 5 brute force alerts in Splunk format
python -m simulator.generate_alerts --type brute_force --count 5 --siem splunk

# Send 3 malware alerts with 2-second delay
python -m simulator.generate_alerts --type malware_detected --count 3 --delay 2
```

### Run Tests

```bash
python -m pytest tests/ -v
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/alerts` | Receive a single SIEM alert |
| `POST` | `/api/alerts/bulk` | Receive multiple alerts at once |
| `GET` | `/api/alerts` | List alerts (with filtering) |
| `GET` | `/api/alerts/{id}` | Get alert details |
| `GET` | `/api/stats` | Get alert statistics |
| `DELETE` | `/api/alerts/{id}` | Delete an alert |
| `GET` | `/health` | Health check |

### Example: Send an Alert

```bash
curl -X POST http://localhost:8000/api/alerts \
  -H "Content-Type: application/json" \
  -d '{
    "source": "generic",
    "payload": {
      "timestamp": "2026-06-11T10:00:00Z",
      "alert_type": "brute_force",
      "severity": "high",
      "source_ip": "103.24.55.12",
      "target": "web-server-01",
      "description": "50 failed SSH login attempts from 103.24.55.12"
    }
  }'
```

## Project Structure

```
soar-engine/
├── app/                          # Main application
│   ├── main.py                   # FastAPI entry point
│   ├── config.py                 # Environment configuration
│   ├── models/                   # Pydantic data models
│   │   ├── alert.py             # Alert schemas (Raw, Normalized, Summary)
│   │   └── enrichment.py        # Enrichment result schemas
│   ├── routers/                  # API route handlers
│   │   ├── webhooks.py          # POST /api/alerts (webhook receiver)
│   │   └── alerts.py            # GET /api/alerts (query & stats)
│   ├── services/                 # Business logic
│   │   └── normalizer.py        # Multi-SIEM alert normalization
│   ├── playbooks/                # Response playbooks (Week 3)
│   ├── containment/              # Containment modules (Week 3)
│   └── db/                       # Data persistence
│       └── store.py             # In-memory alert store
├── simulator/                    # SIEM alert simulator
│   └── generate_alerts.py       # Generates fake alerts for testing
├── dashboard/                    # Web dashboard (Week 4)
├── tests/                        # Unit tests
│   ├── test_normalizer.py
│   └── test_store.py
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

## Development Roadmap

- [x] **Week 1**: Webhook Ingestion & Data Normalization
- [ ] **Week 2**: Automated Threat Enrichment (AbuseIPDB, VirusTotal)
- [ ] **Week 3**: Orchestration Playbook Execution & Containment
- [ ] **Week 4**: SOC Dashboard & Deployment

## Author

**Gobindo Debnath Dipro**
- Cyber Security Intern @ Infotact Solutions (Batch-18)
- GitHub: [@dipro20debnath](https://github.com/dipro20debnath)
- Email: diprodebnath200@gmail.com

## License

This project is part of the Infotact Solutions Technical Internship Program.
