# Phishing Analysis Scoring Criteria

## Overview

Each email is scored 0-100 based on 11 analysis layers. Higher scores indicate stronger phishing indicators.

## Scoring by Layer

| Layer | Category | Max Score | Checks |
|-------|----------|-----------|--------|
| 1 | Sender Analysis | 35 | Display name spoofing (15), free email provider (5), suspicious TLD (15) |
| 2 | Subject Analysis | 15 | Phishing keywords (10), all caps (5) |
| 3 | Body Content | 30 | Generic greetings (10), credential requests (20) |
| 4 | URL Analysis | 40 | IP address URLs (20), shorteners (10), suspicious TLD (15), gibberish domain (15) |
| 5 | Attachment Analysis | 40 | Critical extensions (25), high-risk archives (15), medium-risk docs (5) |
| 6 | Header Authentication | 25 | SPF fail (15), DKIM fail (10) |
| 7 | Urgency Tactics | 10 | Multiple urgency patterns (10), single (5) |
| 8 | Brand Impersonation | 20 | Brand mention + domain mismatch (20) |
| 9 | ISP + Suspicious URL | 15 | ISP sender with suspicious links (15) |
| 10 | Gov/Postal Impersonation | 20 | Government/postal keyword + wrong domain (20) |
| 11 | Tracking Services | 10 | Non-legitimate tracking/redirect (5) |

## Risk Level Thresholds

| Score | Level | Color | Action |
|-------|-------|-------|--------|
| 0-14 | Safe | Green | No action needed |
| 15-29 | Low | Yellow | Monitor |
| 30-49 | Medium | Orange | Review carefully |
| 50-69 | High | Red | Likely phishing, do not interact |
| 70-100 | Critical | Dark Red | Confirmed phishing, report and block |

## Score Capping

Each layer has a maximum contribution cap to prevent single-layer dominance.
For example, even if an email has 10 suspicious URLs, Layer 4 can only contribute 40 points.

## Safe Overrides

The following are excluded from scoring:
- Microsoft 365 SafeLinks rewrites (`safelinks.protection.outlook.com`)
- Proofpoint URL Defense (`urldefense.proofpoint.com`)
- Mimecast and Barracuda security rewrites
