# Security Automation Platform

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green?logo=fastapi)
![Security](https://img.shields.io/badge/Security-CIRCL%20CVE-red?logo=shield)
![License](https://img.shields.io/badge/License-MIT-green)

> A RAG-based security vulnerability analysis platform with OS fingerprinting, CVE mapping, and phishing email detection.

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
│  │ OS Detector │  │ CVE Collector│  │  Phishing   │              │
│  │(User-Agent) │  │ + RAG Engine│  │  Analyzer   │              │
│  └─────────────┘  └──────┬──────┘  └─────────────┘              │
└──────────────────────────┼──────────────────────────────────────┘
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
   │  CIRCL CVE  │  │  NIST NVD   │  │  CISA KEV   │
   │     API     │  │     API     │  │   Catalog   │
   └─────────────┘  └─────────────┘  └─────────────┘
```

## Features

### CVE Vulnerability Analysis
- **OS Fingerprinting**: Auto-detect OS via User-Agent parsing
- **CIRCL CVE API**: Real-time vulnerability data
- **CISA KEV Integration**: Known Exploited Vulnerabilities flagging
- **Vendor Security Links**: Direct links to 15+ vendor security pages
- **LLM-powered Analysis**: Contextual remediation recommendations

### Phishing Email Analyzer
- **.eml File Parsing**: Extract sender, subject, body, URLs
- **Threat Indicator Extraction**: Detect suspicious patterns
- **Risk Scoring**: 0-10 automated risk assessment
- **LLM Classification**: SAFE / SUSPICIOUS / MALICIOUS

### UI/UX
- Animated bubble loading with progress tracking
- Real-time CVE search and filtering
- Responsive modern interface

## Tech Stack

| Category | Technologies |
|----------|-------------|
| Backend | Python, FastAPI, Pydantic |
| AI/ML | Sentence Transformers, LanceDB |
| Frontend | HTML5, CSS3, JavaScript |

## Data Sources

This project uses the following public APIs and data sources:

| Source | URL | Purpose | License |
|--------|-----|---------|---------|
| **CIRCL CVE API** | https://vulnerability.circl.lu/api | Primary CVE data | Public API |
| **NIST NVD** | https://services.nvd.nist.gov/rest/json/cves/2.0 | Fallback CVE data | Public Domain |
| **CISA KEV** | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | Known Exploited Vulnerabilities | CC0 1.0 |
| Google Safe Browsing | https://safebrowsing.googleapis.com | URL reputation (optional) | Requires API key |
| VirusTotal | https://www.virustotal.com/api/v3 | URL analysis (optional) | Requires API key |

> **Disclaimer:** This project is not endorsed by CIRCL, NIST, CISA, or any government agency. Data is provided for educational and research purposes only.

## Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/yourusername/security-automation-platform.git
cd security-automation-platform
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

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/health | Health check |
| POST | /api/os-detect | Detect OS from User-Agent |
| POST | /api/cve/analyze | Analyze CVE for specific OS |
| POST | /api/cve/search | Search CVE by ID or keyword |
| POST | /api/phishing/analyze | Analyze email for phishing |
| GET | /api/versions | Get OS version information |

## License

MIT License - see [LICENSE](LICENSE)

## Author

**Sunday Chen**
- [LinkedIn](https://www.linkedin.com/in/sunday-chen/)
