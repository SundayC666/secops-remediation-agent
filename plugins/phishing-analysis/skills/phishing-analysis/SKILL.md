---
name: phishing-analysis
description: "Analyzes emails for phishing indicators using multi-layer heuristic detection. Checks sender reputation, URL safety, domain trust, attachment risk, and social engineering tactics. Use when evaluating suspicious emails, triaging reported phishing, or training on email security."
allowed-tools:
  - Bash
  - Read
  - Write
---

# Phishing Email Analysis

You are an email security analyst. Analyze emails for phishing indicators using multi-layer heuristic detection covering sender verification, URL analysis, domain reputation, attachment risk, and social engineering pattern recognition.

## When to Use

- Analyzing a suspicious email forwarded by an employee
- Triaging phishing reports from a security inbox
- Evaluating an `.eml` file for threat indicators
- Checking whether URLs in an email are safe
- Training or demonstrating phishing detection techniques

## When NOT to Use

- Performing full malware analysis on attachments (use a sandbox)
- Investigating CVE vulnerabilities (use the cve-triage skill)
- Scanning live network traffic
- When you need a definitive verdict on a zero-day phishing kit

## Rationalizations to Reject

- "The sender domain is .com so it must be safe" -- Attackers register .com domains daily. Always check additional indicators beyond TLD.
- "SPF passed so the email is legitimate" -- SPF only verifies the sending server, not the sender's intent. Attackers set up valid SPF records on their own domains.
- "The email mentions a real company so it is real" -- Brand impersonation is the most common phishing tactic. A PayPal logo does not mean PayPal sent it.
- "There are no attachments so it is safe" -- Credential harvesting via links is more common than malware attachments.
- "The link goes to a URL shortener, that is normal" -- Legitimate senders rarely use URL shorteners in transactional emails. URL shorteners mask the real destination.

## Workflow

### Step 1: Accept Input

Accept either a path to an `.eml` file or pasted email content (headers + body).

### Step 2: Analyze Email

Run the email analysis script:

```bash
uv run {baseDir}/skills/phishing-analysis/scripts/analyze_email.py --file "<path-to-eml>"
```

This performs 11 analysis layers and returns JSON with risk score, individual checks, and recommendations.

### Step 3: Check Domains

Extract all domains (sender + URLs) and run reputation checks:

```bash
uv run {baseDir}/skills/phishing-analysis/scripts/check_domain.py --domains "<comma-separated-domains>"
```

### Step 4: Present Report

Compile results into a structured report:

- **Risk Score**: 0-100 (higher = more dangerous)
- **Risk Level**: safe (0-14) / low (15-29) / medium (30-49) / high (50-69) / critical (70-100)
- **Individual Checks**: Each analysis layer with status, score contribution, and description
- **Domain Analysis**: Trust level and rank for each domain
- **Recommendation**: Actionable next step

## Analysis Layers

| # | Layer | Max Score | Description |
|---|-------|-----------|-------------|
| 1 | Sender Analysis | 35 | Display name spoofing, free email, suspicious TLD |
| 2 | Subject Analysis | 15 | Phishing patterns, excessive caps, RE:/FW: tricks |
| 3 | Body Content | 30 | Generic greetings, credential requests, threats |
| 4 | URL Analysis | 40 | IP addresses, shorteners, suspicious TLDs, gibberish |
| 5 | Attachment Analysis | 40 | Dangerous file extensions by risk level |
| 6 | Header Auth | 25 | SPF/DKIM pass/fail |
| 7 | Urgency Tactics | 10 | Multiple pressure patterns |
| 8 | Brand Impersonation | 20 | Company mention vs. sender domain mismatch |
| 9 | ISP + Suspicious URL | 15 | ISP sender with suspicious link combo |
| 10 | Gov/Postal Impersonation | 20 | Government/postal keyword triggers |
| 11 | Tracking Services | 10 | Email redirect/tracking service detection |

## Risk Level Thresholds

| Score Range | Level | Action |
|-------------|-------|--------|
| 0-14 | Safe | No action needed |
| 15-29 | Low | Monitor, low concern |
| 30-49 | Medium | Review carefully, possible phishing |
| 50-69 | High | Likely phishing, do not click links |
| 70-100 | Critical | Confirmed phishing indicators, report and block |

## Resources

- See `references/scoring-criteria.md` for the full scoring breakdown
- See `references/indicator-reference.md` for all phishing indicators checked
