---
name: phishing
description: "Analyzes an email for phishing indicators"
argument-hint: "<path-to-eml-file>"
allowed-tools:
  - Bash
  - Read
  - Write
---

# Analyze Email for Phishing

Invoke the phishing-analysis skill to check an email for phishing indicators.

## Steps

1. If given a file path, analyze that `.eml` file:
```bash
uv run {baseDir}/skills/phishing-analysis/scripts/analyze_email.py --file "$ARGUMENTS"
```

2. If the user provides email text directly (not a file), save it to a temp file first, then analyze.

3. Extract all domains from the results (sender domain + URL domains) and check reputation:
```bash
uv run {baseDir}/skills/phishing-analysis/scripts/check_domain.py --domains "<extracted-domains>"
```

4. Present results as a structured phishing analysis report with:
   - Risk score and level
   - Summary of findings by layer
   - Domain reputation results
   - Actionable recommendation
