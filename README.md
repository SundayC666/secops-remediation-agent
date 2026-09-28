# Security Automation Platform

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green?logo=fastapi)
![Security](https://img.shields.io/badge/Security-NVD%20CVE-red?logo=shield)
![License](https://img.shields.io/badge/License-MIT-green)

> **Status (Sept 2026):** This project is being repositioned. The new direction is described in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (in progress). The phishing analyzer now lives on the [`phishing-analyzer`](https://github.com/SundayC666/secops-remediation-agent/tree/phishing-analyzer) branch.

A security tool for CVE vulnerability lookup. Uses **CPE-based search** against NIST NVD with CISA KEV cross-referencing.

**[Live Demo](https://security-automation-platform.onrender.com)** *(Free tier - initial load may take 30-60 seconds)*

## What This Tool Does

| Category | Capability | Description |
|----------|------------|-------------|
| **CVE Lookup** | CPE-based NVD search | Map product names to CPE identifiers and query NIST NVD |
| | CISA KEV flagging | Flag CVEs that are actively exploited in the wild |
| **Optional LLM** | Deep analysis | Supplemental CVE analysis via local Ollama (not required) |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Frontend (Static)                        │
│  ┌─────────────┐  ┌─────────────┐                               │
│  │   app.js    │  │ cve_analyzer│                               │
│  │ (OS Detect) │  │    .js      │                               │
│  └──────┬──────┘  └──────┬──────┘                               │
└─────────┼────────────────┼──────────────────────────────────────┘
          │                │
          ▼                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      FastAPI Backend                             │
│  ┌─────────────┐  ┌─────────────┐                               │
│  │ /api/os-    │  │ /api/cve/   │                               │
│  │   detect    │  │   analyze   │                               │
│  └──────┬──────┘  └──────┬──────┘                               │
│         │                │                                       │
│         ▼                ▼                                       │
│  ┌─────────────┐  ┌─────────────┐                               │
│  │ OS Detector │  │ CVE Search  │                               │
│  │(User-Agent) │  │  Pipeline   │                               │
│  └─────────────┘  └──────┬──────┘                               │
└──────────────────────────┼──────────────────────────────────────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
       ┌─────────────┐          ┌─────────────┐
       │  NIST NVD   │          │  CISA KEV   │
       │ CPE Search  │          │   Catalog   │
       └─────────────┘          └─────────────┘
```

### CVE Search Pipeline

**NVD CPE Search**: Precise search using CPE (Common Platform Enumeration) identifiers
   - Maps keywords like "Windows 11" to multiple version-specific CPEs (21h2, 22h2, 23h2, 24h2)
   - Returns recent CVEs (2024-2026) with deduplication across versions

## Features

### CVE Vulnerability Lookup
- **OS Detection**: Auto-detect OS via User-Agent parsing
- **NVD CPE Search**: Map product names to CPE identifiers and query NVD API
- **CISA KEV Cross-referencing**: Flag actively exploited vulnerabilities
- **Vendor Security Links**: Direct links to 15+ vendor security pages
- **LLM Analysis (Optional)**: Supplemental remediation recommendations via local Ollama

## Tech Stack

| Category | Technologies |
|----------|-------------|
| Backend | Python 3.9+, FastAPI, Pydantic |
| LLM (Optional) | LangChain + Ollama (local inference) |
| Frontend | HTML5, CSS3, Vanilla JavaScript |

## Data Sources

This project uses the following public APIs and data sources:

| Source | URL | Purpose | License |
|--------|-----|---------|---------|
| **NIST NVD** | https://services.nvd.nist.gov/rest/json/cves/2.0 | Primary CVE data (CPE-based search) | Public Domain |
| **CISA KEV** | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | Known Exploited Vulnerabilities | CC0 1.0 |

> **Disclaimer:** This project is not endorsed by NIST, CISA, or any government agency. Data is provided for educational and research purposes only.

## Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/SundayC666/secops-remediation-agent.git
cd secops-remediation-agent
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your settings (optional for local LLM)
```

### 3. Run

```bash
python main.py
# Open http://localhost:8000
```

### 4. Enable LLM Features (Optional)

For AI-powered deep analysis and remediation recommendations, install [Ollama](https://ollama.ai):

```bash
# Install Ollama from https://ollama.ai
ollama pull llama3.2:3b
```

The application will automatically detect Ollama and enable:
- **Deep CVE Analysis**: Supplemental remediation recommendations

> **Note:** The [Live Demo](https://security-automation-platform.onrender.com) runs without Ollama. LLM features are only available when running locally with Ollama installed.

## Security

- **CORS**: Restricted to specific origins, GET/POST only
- **Security Headers**: X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy
- **Rate Limiting**: slowapi on all endpoints (10-60 req/min per endpoint)
- **Input Sanitization**: html.escape, filename validation, content length limits
- **Dependencies**: All pinned to exact versions in requirements.txt

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/health | Health check |
| GET | /api/os/detect | Detect OS from User-Agent |
| GET | /api/cve/latest | Get latest CVEs for detected OS |
| POST | /api/cve/analyze | Analyze CVE for specific query |
| POST | /api/cve/deep-analyze | LLM-powered CVE analysis |
| GET | /api/versions/buttons | Get quick search buttons |

## Agent Skills

This project includes standalone security skills that work independently of the FastAPI server. Plugin structure follows the [Trail of Bits skills](https://github.com/trailofbits/skills) open standard and can be used directly in any compatible AI coding assistant.

### Available Skills

| Skill | Command | Description |
|-------|---------|-------------|
| **CVE Triage** | `/triage <product>` | NVD vulnerability lookup with CISA KEV cross-referencing and SLA prioritization |

### Standalone Usage

Skills run independently via `uv run` with no server required:

```bash
# CVE triage
uv run plugins/cve-triage/skills/cve-triage/scripts/nvd_lookup.py --product "windows 11"
uv run plugins/cve-triage/skills/cve-triage/scripts/kev_check.py --cve-ids "CVE-2024-21351"
```

Scripts use [PEP 723](https://peps.python.org/pep-0723/) inline metadata for automatic dependency resolution.

## License

MIT License - see [LICENSE](LICENSE)

## Author

**Sunday Chen**
- [LinkedIn](https://www.linkedin.com/in/sunday-chen/)
