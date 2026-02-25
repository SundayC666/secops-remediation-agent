#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = ["httpx>=0.28"]
# ///
"""
Phishing Email Analyzer - Multi-layer heuristic email analysis.
Performs 11 analysis checks on email content to detect phishing indicators.
"""

import argparse
import email
import json
import math
import re
import sys
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".click", ".link", ".work", ".date", ".download",
    ".win", ".bid", ".stream", ".racing", ".review", ".cricket",
    ".science", ".party", ".gq", ".cf", ".ga", ".ml", ".tk",
    ".vip", ".icu", ".buzz", ".monster", ".loan", ".online", ".site",
    ".club", ".wang", ".men", ".cam", ".rest", ".life", ".live",
    ".space", ".tech", ".store", ".fun", ".zone", ".pro", ".pw",
    ".cc", ".su", ".cn", ".ru", ".ua",
]

# ISP/consumer email domains
ISP_DOMAINS = [
    "windstream.net", "comcast.net", "verizon.net", "att.net", "cox.net",
    "charter.net", "spectrum.net", "frontier.com", "centurylink.net",
    "earthlink.net", "sbcglobal.net", "bellsouth.net",
]

# Commonly spoofed brands
SPOOFED_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "netflix", "bank", "chase", "wellsfargo", "citibank", "usps",
    "fedex", "dhl", "ups", "irs", "dropbox", "linkedin", "coinbase",
]

# Government/postal keywords
GOV_POSTAL_KEYWORDS = {
    "usps": "usps.com", "royal mail": "royalmail.com",
    "canada post": "canadapost.ca", "irs": "irs.gov",
    "hmrc": "gov.uk",
}

# Email tracking services
TRACKING_SERVICES = [
    "mailgun", "sendgrid", "mailchimp", "constantcontact",
    "campaign-archive", "list-manage", "hubspot", "marketo",
    "click.", "track.", "links.", "redirect.", "trk.",
]

# Legitimate email security rewrites (not phishing indicators)
LEGIT_SECURITY_SERVICES = [
    "safelinks.protection.outlook.com", "urldefense.proofpoint.com",
    "mimecast.com", "barracuda.com",
]

# Dangerous file extensions by risk level
DANGEROUS_EXTENSIONS = {
    "critical": [".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs",
                 ".vbe", ".js", ".jse", ".ws", ".wsf", ".msc", ".msi", ".hta"],
    "high": [".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".img"],
    "medium": [".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".pdf"],
    "low": [".docx", ".xlsx", ".pptx", ".txt", ".csv"],
}

# URL shorteners
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "short.io",
]


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    counter = Counter(text.lower())
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counter.values())


def is_gibberish_domain(domain: str) -> Tuple[bool, float]:
    """Detect if a domain name looks like random gibberish."""
    parts = domain.split(".")
    main_part = parts[-2] if len(parts) >= 2 else parts[0]
    if len(main_part) <= 3:
        return False, 0.0

    entropy = calculate_entropy(main_part)
    vowels = set("aeiou")
    vowel_count = sum(1 for c in main_part.lower() if c in vowels)
    vowel_ratio = vowel_count / len(main_part)

    if entropy > 2.3 and vowel_ratio < 0.25:
        return True, entropy
    if entropy > 3.8:
        return True, entropy
    if re.search(r"[bcdfghjklmnpqrstvwxz]{4,}", main_part.lower()):
        return True, entropy
    if len(main_part) > 4 and vowel_count == 0:
        return True, entropy
    return False, entropy


def parse_eml(file_path: str) -> Dict[str, Any]:
    """Parse a .eml file into structured email content."""
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        msg = email.message_from_file(f)

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    body = payload.decode("utf-8", errors="replace")
                    break
        if not body:
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    payload = part.get_payload(decode=True)
                    if payload:
                        body = payload.decode("utf-8", errors="replace")
                        break
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode("utf-8", errors="replace")

    urls = re.findall(r'https?://[^\s<>"\']+', body)
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            filename = part.get_filename()
            if filename:
                attachments.append(filename)

    return {
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "subject": msg.get("Subject", ""),
        "body": body,
        "urls": urls,
        "attachments": attachments,
        "headers": {
            "received_spf": msg.get("Received-SPF", ""),
            "dkim_signature": msg.get("DKIM-Signature", ""),
            "authentication_results": msg.get("Authentication-Results", ""),
            "return_path": msg.get("Return-Path", ""),
            "x_mailer": msg.get("X-Mailer", ""),
        },
    }


def analyze_email(content: Dict[str, Any]) -> Dict[str, Any]:
    """Perform 11-layer phishing analysis on email content."""
    checks = []
    risk_score = 0

    from_addr = content.get("from", "")
    subject = content.get("subject", "")
    body = content.get("body", "")
    urls = content.get("urls", [])
    attachments = content.get("attachments", [])
    headers = content.get("headers", {})

    # Extract sender domain
    domain_match = re.search(r"@([a-zA-Z0-9.-]+)", from_addr)
    sender_domain = domain_match.group(1).lower() if domain_match else ""

    # === Layer 1: Sender Analysis ===
    layer1_score = 0

    # Display name spoofing
    display_match = re.match(r'"?([^"<]+)"?\s*<', from_addr)
    if display_match:
        display_name = display_match.group(1).strip().lower()
        if "@" in display_name:
            layer1_score += 15
            checks.append({"layer": 1, "category": "Sender Analysis", "name": "Display name contains email",
                           "status": "danger", "score": 15, "description": "Display name contains an email address (common spoofing technique)"})

    # Free email provider for business context
    free_providers = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com"]
    if sender_domain in free_providers:
        layer1_score += 5
        checks.append({"layer": 1, "category": "Sender Analysis", "name": "Free email provider",
                       "status": "warning", "score": 5, "description": f"Sent from free provider: {sender_domain}"})

    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if sender_domain.endswith(tld):
            layer1_score += 15
            checks.append({"layer": 1, "category": "Sender Analysis", "name": "Suspicious TLD",
                           "status": "danger", "score": 15, "description": f"Sender domain uses suspicious TLD: {tld}"})
            break

    risk_score += min(layer1_score, 35)

    # === Layer 2: Subject Analysis ===
    layer2_score = 0
    subject_lower = subject.lower()
    phishing_subjects = ["urgent", "verify your account", "suspended", "unusual activity",
                         "confirm your identity", "security alert", "password expire",
                         "action required", "limited time", "your account has been"]
    for pattern in phishing_subjects:
        if pattern in subject_lower:
            layer2_score += 10
            checks.append({"layer": 2, "category": "Subject Analysis", "name": "Phishing keyword in subject",
                           "status": "warning", "score": 10, "description": f"Subject contains phishing pattern: '{pattern}'"})
            break

    if subject.isupper() and len(subject) > 10:
        layer2_score += 5
        checks.append({"layer": 2, "category": "Subject Analysis", "name": "All caps subject",
                       "status": "warning", "score": 5, "description": "Subject is entirely uppercase (pressure tactic)"})

    risk_score += min(layer2_score, 15)

    # === Layer 3: Body Content Analysis ===
    layer3_score = 0
    body_lower = body.lower()

    generic_greetings = ["dear customer", "dear user", "dear sir", "dear valued", "dear account holder"]
    for greeting in generic_greetings:
        if greeting in body_lower:
            layer3_score += 10
            checks.append({"layer": 3, "category": "Body Content", "name": "Generic greeting",
                           "status": "warning", "score": 10, "description": f"Uses generic greeting: '{greeting}'"})
            break

    credential_requests = ["enter your password", "confirm your credentials", "verify your identity",
                           "update your payment", "click here to verify", "log in to confirm"]
    for req in credential_requests:
        if req in body_lower:
            layer3_score += 20
            checks.append({"layer": 3, "category": "Body Content", "name": "Credential request",
                           "status": "danger", "score": 20, "description": f"Requests credentials: '{req}'"})
            break

    risk_score += min(layer3_score, 30)

    # === Layer 4: URL Analysis ===
    layer4_score = 0
    for url in urls[:10]:
        parsed = urlparse(url)
        url_domain = parsed.hostname or ""

        # Skip legitimate security rewrites
        if any(svc in url_domain for svc in LEGIT_SECURITY_SERVICES):
            continue

        # IP address in URL
        if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url_domain):
            layer4_score += 20
            checks.append({"layer": 4, "category": "URL Analysis", "name": "IP address URL",
                           "status": "critical", "score": 20, "description": f"URL uses IP address: {url_domain}"})

        # URL shortener
        if any(url_domain.endswith(s) for s in URL_SHORTENERS):
            layer4_score += 10
            checks.append({"layer": 4, "category": "URL Analysis", "name": "URL shortener",
                           "status": "warning", "score": 10, "description": f"URL uses shortener: {url_domain}"})

        # Suspicious TLD in URL
        for tld in SUSPICIOUS_TLDS:
            if url_domain.endswith(tld):
                layer4_score += 15
                checks.append({"layer": 4, "category": "URL Analysis", "name": "Suspicious URL TLD",
                               "status": "danger", "score": 15, "description": f"URL uses suspicious TLD: {url_domain}"})
                break

        # Gibberish domain
        is_gib, entropy = is_gibberish_domain(url_domain)
        if is_gib:
            layer4_score += 15
            checks.append({"layer": 4, "category": "URL Analysis", "name": "Gibberish domain",
                           "status": "danger", "score": 15, "description": f"URL domain appears randomly generated: {url_domain} (entropy: {entropy:.2f})"})

    risk_score += min(layer4_score, 40)

    # === Layer 5: Attachment Analysis ===
    layer5_score = 0
    attachment_analyses = []
    for filename in attachments:
        ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        risk_level = "safe"
        ext_score = 0

        if ext in DANGEROUS_EXTENSIONS["critical"]:
            risk_level, ext_score = "critical", 25
        elif ext in DANGEROUS_EXTENSIONS["high"]:
            risk_level, ext_score = "high", 15
        elif ext in DANGEROUS_EXTENSIONS["medium"]:
            risk_level, ext_score = "medium", 5

        if ext_score > 0:
            layer5_score += ext_score
            checks.append({"layer": 5, "category": "Attachment", "name": f"Dangerous attachment: {filename}",
                           "status": risk_level, "score": ext_score, "description": f"Attachment '{filename}' has {risk_level}-risk extension"})

        attachment_analyses.append({"filename": filename, "extension": ext, "risk_level": risk_level})

    risk_score += min(layer5_score, 40)

    # === Layer 6: Header Authentication ===
    layer6_score = 0
    auth_results = headers.get("authentication_results", "").lower()
    spf_result = headers.get("received_spf", "").lower()

    if "spf=fail" in auth_results or "fail" in spf_result:
        layer6_score += 15
        checks.append({"layer": 6, "category": "Authentication", "name": "SPF failed",
                       "status": "danger", "score": 15, "description": "SPF authentication failed (sender may be spoofed)"})
    elif "spf=pass" in auth_results or "pass" in spf_result:
        checks.append({"layer": 6, "category": "Authentication", "name": "SPF passed",
                       "status": "safe", "score": 0, "description": "SPF authentication passed"})

    if "dkim=fail" in auth_results:
        layer6_score += 10
        checks.append({"layer": 6, "category": "Authentication", "name": "DKIM failed",
                       "status": "danger", "score": 10, "description": "DKIM signature verification failed"})
    elif "dkim=pass" in auth_results:
        checks.append({"layer": 6, "category": "Authentication", "name": "DKIM passed",
                       "status": "safe", "score": 0, "description": "DKIM signature verified"})

    risk_score += min(layer6_score, 25)

    # === Layer 7: Urgency Tactics ===
    layer7_score = 0
    urgency_patterns = ["act now", "immediately", "within 24 hours", "account will be closed",
                        "last chance", "final warning", "expires today", "don't delay"]
    urgency_count = sum(1 for p in urgency_patterns if p in body_lower)
    if urgency_count >= 2:
        layer7_score = 10
        checks.append({"layer": 7, "category": "Urgency Tactics", "name": "Multiple urgency patterns",
                       "status": "danger", "score": 10, "description": f"Found {urgency_count} urgency pressure patterns"})
    elif urgency_count == 1:
        layer7_score = 5
        checks.append({"layer": 7, "category": "Urgency Tactics", "name": "Urgency language",
                       "status": "warning", "score": 5, "description": "Email uses urgency language"})

    risk_score += min(layer7_score, 10)

    # === Layer 8: Brand Impersonation ===
    layer8_score = 0
    for brand in SPOOFED_BRANDS:
        if brand in body_lower or brand in subject_lower:
            if brand not in sender_domain:
                layer8_score += 20
                checks.append({"layer": 8, "category": "Brand Impersonation", "name": f"Possible {brand} impersonation",
                               "status": "danger", "score": 20,
                               "description": f"Email mentions '{brand}' but sender domain is '{sender_domain}'"})
                break

    risk_score += min(layer8_score, 20)

    # === Layer 9: ISP Sender + Suspicious URL Combo ===
    layer9_score = 0
    is_isp = any(sender_domain.endswith(isp) for isp in ISP_DOMAINS)
    has_suspicious_url = any(
        any(url_domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
        for url in urls if (url_domain := urlparse(url).hostname or "")
    )
    if is_isp and has_suspicious_url:
        layer9_score = 15
        checks.append({"layer": 9, "category": "ISP + Suspicious URL", "name": "ISP sender with suspicious links",
                       "status": "danger", "score": 15, "description": "Email from ISP address contains links to suspicious domains"})

    risk_score += min(layer9_score, 15)

    # === Layer 10: Government/Postal Impersonation ===
    layer10_score = 0
    combined_text = (subject_lower + " " + body_lower)
    for keyword, legit_domain in GOV_POSTAL_KEYWORDS.items():
        if keyword in combined_text and legit_domain not in sender_domain:
            layer10_score += 20
            checks.append({"layer": 10, "category": "Gov/Postal Impersonation", "name": f"{keyword} impersonation",
                           "status": "critical", "score": 20,
                           "description": f"References '{keyword}' but not sent from {legit_domain}"})
            break

    risk_score += min(layer10_score, 20)

    # === Layer 11: Tracking/Redirect Services ===
    layer11_score = 0
    for url in urls[:10]:
        url_domain = urlparse(url).hostname or ""
        if any(svc in url_domain for svc in LEGIT_SECURITY_SERVICES):
            continue
        if any(svc in url_domain for svc in TRACKING_SERVICES):
            layer11_score += 5
            checks.append({"layer": 11, "category": "Tracking Services", "name": "Email tracking detected",
                           "status": "warning", "score": 5, "description": f"URL uses tracking/redirect service: {url_domain}"})
            break

    risk_score += min(layer11_score, 10)

    # Determine risk level
    if risk_score >= 70:
        risk_level = "critical"
    elif risk_score >= 50:
        risk_level = "high"
    elif risk_score >= 30:
        risk_level = "medium"
    elif risk_score >= 15:
        risk_level = "low"
    else:
        risk_level = "safe"

    recommendations = {
        "critical": "Do NOT click any links or open attachments. Report to your security team immediately. Block the sender.",
        "high": "Likely phishing. Do not interact with the email. Forward to your security team for investigation.",
        "medium": "Suspicious indicators found. Verify the sender through a separate channel before taking any action.",
        "low": "Minor concerns detected. Exercise normal caution.",
        "safe": "No significant phishing indicators detected.",
    }

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "is_phishing": risk_score >= 50,
        "recommendation": recommendations[risk_level],
        "sender": from_addr,
        "sender_domain": sender_domain,
        "subject": subject,
        "url_count": len(urls),
        "attachment_count": len(attachments),
        "checks": checks,
        "attachments": attachment_analyses,
    }


def main():
    parser = argparse.ArgumentParser(description="Analyze email for phishing indicators")
    parser.add_argument("--file", help="Path to .eml file")
    args = parser.parse_args()

    if args.file:
        content = parse_eml(args.file)
    else:
        # Read from stdin as raw text
        raw = sys.stdin.read()
        if not raw.strip():
            print("Provide --file <path> or pipe email content via stdin.", file=sys.stderr)
            sys.exit(1)
        content = {
            "from": "", "to": "", "subject": "", "body": raw,
            "urls": re.findall(r"https?://[^\s<>\"']+", raw),
            "attachments": [],
            "headers": {},
        }

    result = analyze_email(content)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
