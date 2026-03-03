# Security Automation Platform

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green?logo=fastapi)
![Semantic Search](https://img.shields.io/badge/Semantic%20Search-Sentence%20Transformers-orange?logo=huggingface)
![Security](https://img.shields.io/badge/Security-NVD%20CVE-red?logo=shield)
![License](https://img.shields.io/badge/License-MIT-green)

A security tool for CVE vulnerability lookup and phishing email detection. Uses **CPE-based search** against NIST NVD with CISA KEV cross-referencing, and **heuristic-based phishing analysis** with domain reputation scoring. Includes a semantic search fallback using Sentence Transformers and ChromaDB.

**[Live Demo](https://security-automation-platform.onrender.com)** *(Free tier - initial load may take 30-60 seconds)*

## What This Tool Does

| Category | Capability | Description |
|----------|------------|-------------|
| **CVE Lookup** | CPE-based NVD search | Map product names to CPE identifiers and query NIST NVD |
| | CISA KEV flagging | Flag CVEs that are actively exploited in the wild |
| | Semantic search fallback | Find related CVEs via Sentence Transformers when CPE returns no results |
| **Phishing Detection** | .eml file parsing | Extract sender, headers, body, URLs, and attachments |
| | Heuristic analysis | 17 rule-based checks (spoofing, suspicious TLD, entropy, urgency, etc.) |
| | Domain reputation | Check sender/URL domains against Tranco top-1M list |
| | Risk scoring | 0-100 score based on weighted heuristic results |
| **Optional LLM** | Deep analysis | Supplemental CVE/phishing analysis via local Ollama (not required) |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Frontend (Static)                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │   app.js    │  │ cve_analyzer│  │  phishing   │              │
│  │ (OS Detect) │  │    .js      │  │ _analyzer.js│              │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘              │
└─────────┼────────────────┼────────────────┼─────────────────────┘
          │                │                │
          ▼                ▼                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      FastAPI Backend                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │ /api/os-    │  │ /api/cve/   │  │/api/phishing│              │
│  │   detect    │  │   analyze   │  │  /analyze   │              │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘              │
│         │                │                │                      │
│         ▼                ▼                ▼                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │ OS Detector │  │ CVE Search  │  │  Phishing   │              │
│  │(User-Agent) │  │  Pipeline   │  │  Analyzer   │              │
│  └─────────────┘  └──────┬──────┘  └─────────────┘              │
└──────────────────────────┼──────────────────────────────────────┘
                           │
         ┌─────────────────┼─────────────────┐
         ▼                 ▼                 ▼
  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
  │  NIST NVD   │   │  RAG Engine │   │  CISA KEV   │
  │ CPE Search  │   │ (Fallback)  │   │   Catalog   │
  │  (Primary)  │   │             │   │             │
  └─────────────┘   └──────┬──────┘   └─────────────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
       ┌─────────────┐          ┌─────────────┐
       │  Sentence   │          │  ChromaDB   │
       │ Transformers│          │ Vector Store│
       └─────────────┘          └─────────────┘
```

### CVE Search Pipeline

1. **NVD CPE Search (Primary)**: Precise search using CPE (Common Platform Enumeration) identifiers
   - Maps keywords like "Windows 11" to multiple version-specific CPEs (21h2, 22h2, 23h2, 24h2)
   - Returns recent CVEs (2024-2026) with deduplication across versions

2. **RAG Semantic Search (Fallback)**: When CPE search returns no results
   - Uses Sentence Transformers (`all-MiniLM-L6-v2`) for semantic understanding
   - ChromaDB stores CVE embeddings for fast similarity search
   - Finds related vulnerabilities even with different terminology

## Features

### CVE Vulnerability Lookup
- **OS Detection**: Auto-detect OS via User-Agent parsing
- **NVD CPE Search**: Map product names to CPE identifiers and query NVD API
- **CISA KEV Cross-referencing**: Flag actively exploited vulnerabilities
- **Semantic Search Fallback**: Sentence Transformers + ChromaDB when CPE search returns no results
- **Vendor Security Links**: Direct links to 15+ vendor security pages
- **LLM Analysis (Optional)**: Supplemental remediation recommendations via local Ollama

### Phishing Email Analyzer
- **.eml File Parsing**: Extract sender, subject, body, URLs, attachments
- **Heuristic Detection**: 17 rule-based checks (sender spoofing, suspicious TLD, domain entropy, urgency tactics, SPF/DKIM, brand impersonation, etc.)
- **Domain Reputation**: Tranco top-1M list lookup with Shannon entropy scoring for gibberish domain detection
- **Risk Scoring**: 0-100 weighted score with risk level classification

## Tech Stack

| Category | Technologies |
|----------|-------------|
| Backend | Python 3.9+, FastAPI, Pydantic |
| Semantic Search | Sentence Transformers (all-MiniLM-L6-v2), ChromaDB |
| LLM (Optional) | LangChain + Ollama (local inference) |
| Frontend | HTML5, CSS3, Vanilla JavaScript |

## Data Sources

This project uses the following public APIs and data sources:

| Source | URL | Purpose | License |
|--------|-----|---------|---------|
| **NIST NVD** | https://services.nvd.nist.gov/rest/json/cves/2.0 | Primary CVE data (CPE-based search) | Public Domain |
| **CISA KEV** | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | Known Exploited Vulnerabilities | CC0 1.0 |
| **Tranco List** | https://tranco-list.eu | Domain reputation (top 1M sites) | CC BY-NC-SA 4.0 |
| Google Safe Browsing | https://safebrowsing.googleapis.com | URL reputation (optional) | Requires API key |
| VirusTotal | https://www.virustotal.com/api/v3 | URL analysis (optional) | Requires API key |

### Tranco List Citation

This project uses the Tranco List for domain reputation scoring:

> Le Pochat, V., Van Goethem, T., Tajalizadehkhoob, S., Korczyński, M., & Joosen, W. (2019).
> Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation.
> *Proceedings of the 26th Annual Network and Distributed System Security Symposium (NDSS 2019)*.
> https://doi.org/10.14722/ndss.2019.23386

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
- **Phishing Classification**: Supplemental threat assessment

> **Note:** The [Live Demo](https://security-automation-platform.onrender.com) runs without Ollama. LLM features are only available when running locally with Ollama installed.

## Security

This project implements OWASP Top 10 security controls:

| OWASP | Control | Implementation |
|-------|---------|----------------|
| A01 | Broken Access Control | CORS whitelist, security headers |
| A03 | Injection | Input sanitization, parameterized queries |
| A04 | Insecure Design | Rate limiting (slowapi) on all endpoints |
| A05 | Security Misconfiguration | Security headers (X-Frame-Options, HSTS, X-Content-Type-Options) |
| A06 | Vulnerable Components | All dependencies pinned to exact versions |
| A10 | SSRF | URL validation blocks private IPs, localhost, cloud metadata |

### Security Headers

All responses include:
- `X-Frame-Options: DENY` (clickjacking protection)
- `X-Content-Type-Options: nosniff` (MIME sniffing protection)
- `Strict-Transport-Security` (HTTPS enforcement)
- `Referrer-Policy: strict-origin-when-cross-origin`

### Rate Limiting

| Endpoint | Limit |
|----------|-------|
| CVE Analysis | 30/min |
| Phishing Analysis | 10/min |
| Deep Analysis (LLM) | 10/min |
| Version Refresh | 5/min |

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/health | Health check |
| GET | /api/os/detect | Detect OS from User-Agent |
| GET | /api/cve/latest | Get latest CVEs for detected OS |
| POST | /api/cve/analyze | Analyze CVE for specific query |
| POST | /api/cve/deep-analyze | LLM-powered CVE analysis |
| POST | /api/phishing/analyze | Analyze email for phishing |
| GET | /api/versions/buttons | Get quick search buttons |

## Agent Skills

This project includes standalone security skills that work independently of the FastAPI server. Plugin structure follows the [Trail of Bits skills](https://github.com/trailofbits/skills) open standard and can be used directly in any compatible AI coding assistant.

### Available Skills

| Skill | Command | Description |
|-------|---------|-------------|
| **CVE Triage** | `/triage <product>` | NVD vulnerability lookup with CISA KEV cross-referencing and SLA prioritization |
| **Phishing Analysis** | `/phishing <email.eml>` | Multi-layer phishing detection with domain trust scoring |

### Standalone Usage

Skills run independently via `uv run` with no server required:

```bash
# CVE triage
uv run plugins/cve-triage/skills/cve-triage/scripts/nvd_lookup.py --product "windows 11"
uv run plugins/cve-triage/skills/cve-triage/scripts/kev_check.py --cve-ids "CVE-2024-21351"

# Phishing analysis
uv run plugins/phishing-analysis/skills/phishing-analysis/scripts/analyze_email.py --file suspicious.eml
uv run plugins/phishing-analysis/skills/phishing-analysis/scripts/check_domain.py --domain "example.xyz"
```

Scripts use [PEP 723](https://peps.python.org/pep-0723/) inline metadata for automatic dependency resolution.

## License

MIT License - see [LICENSE](LICENSE)

## Author

**Sunday Chen**
- [LinkedIn](https://www.linkedin.com/in/sunday-chen/)
