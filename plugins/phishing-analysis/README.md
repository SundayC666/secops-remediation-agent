# Phishing Analysis Skill

A security skill for detecting phishing indicators in emails using multi-layer heuristic analysis.

## What It Does

- Parses `.eml` files and extracts sender, subject, body, URLs, and attachments
- Performs 11-layer threat analysis (sender, URLs, headers, social engineering, etc.)
- Checks domain reputation against the Tranco top 1M list
- Produces a risk score (0-100) with actionable recommendations

## Installation

Copy this plugin directory or install via the plugin system:

```bash
# Copy to your skills directory
cp -r plugins/phishing-analysis ~/.claude/skills/
```

## Usage

### Natural Language

- "Analyze this email for phishing"
- "Is this .eml file a phishing attempt?"
- "Check if this email is safe"

### Slash Command

```
/phishing /path/to/suspicious_email.eml
```

### Standalone Scripts

```bash
# Analyze .eml file
uv run scripts/analyze_email.py --file suspicious.eml

# Check domain reputation
uv run scripts/check_domain.py --domain "suspicious-site.xyz"
uv run scripts/check_domain.py --domains "google.com,sketchy.tk,paypa1.com"
```

## Analysis Layers

| # | Check | Description |
|---|-------|-------------|
| 1 | Sender | Display name spoofing, free email, suspicious TLD |
| 2 | Subject | Phishing patterns, excessive caps |
| 3 | Body | Generic greetings, credential requests |
| 4 | URLs | IP addresses, shorteners, gibberish domains |
| 5 | Attachments | Dangerous file extensions |
| 6 | Headers | SPF/DKIM authentication |
| 7 | Urgency | Pressure tactics detection |
| 8 | Brands | Brand impersonation vs. sender mismatch |
| 9 | ISP+URL | ISP sender with suspicious link combo |
| 10 | Gov/Postal | Government/postal impersonation |
| 11 | Tracking | Email tracking/redirect services |

## Data Sources

| Source | License | URL |
|--------|---------|-----|
| Tranco List | CC BY-NC-SA 4.0 | https://tranco-list.eu |

## Author

Sunday Chen
