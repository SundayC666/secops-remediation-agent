#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = ["httpx>=0.28"]
# ///
"""
Domain Reputation Checker - Check domain trust using Tranco list,
suspicious TLD detection, and gibberish domain analysis.
"""

import argparse
import csv
import io
import json
import math
import os
import re
import sys
import tempfile
import time
import zipfile
from collections import Counter
from typing import Dict, List, Optional, Tuple

import httpx

TRANCO_URL = "https://tranco-list.eu/download/XQ256/1000000"
CACHE_DIR = tempfile.gettempdir()
CACHE_FILE = os.path.join(CACHE_DIR, "tranco_top1m.csv")
CACHE_TTL = 86400  # 24 hours

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".click", ".link", ".work", ".date", ".download",
    ".win", ".bid", ".stream", ".gq", ".cf", ".ga", ".ml", ".tk",
    ".vip", ".icu", ".buzz", ".monster", ".loan", ".online", ".site",
    ".club", ".pw", ".cc", ".su",
]

TRUSTED_TLDS = [".gov", ".edu", ".mil"]

# Well-known company domains
TRUSTED_COMPANIES = {
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "facebook.com", "meta.com", "github.com", "linkedin.com",
    "twitter.com", "x.com", "netflix.com", "paypal.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com",
}


def load_tranco_list() -> Dict[str, int]:
    """Load Tranco top 1M list, downloading if needed."""
    # Check cache
    if os.path.exists(CACHE_FILE):
        cache_age = time.time() - os.path.getmtime(CACHE_FILE)
        if cache_age < CACHE_TTL:
            return _parse_tranco_csv(CACHE_FILE)

    # Download fresh list
    try:
        print("Downloading Tranco list...", file=sys.stderr)
        with httpx.Client(timeout=30.0, follow_redirects=True) as client:
            resp = client.get(TRANCO_URL)
            if resp.status_code == 200:
                content = resp.content
                # Check if it's a zip file
                if content[:2] == b"PK":
                    with zipfile.ZipFile(io.BytesIO(content)) as zf:
                        csv_name = zf.namelist()[0]
                        with open(CACHE_FILE, "wb") as f:
                            f.write(zf.read(csv_name))
                else:
                    with open(CACHE_FILE, "wb") as f:
                        f.write(content)
                return _parse_tranco_csv(CACHE_FILE)
    except Exception as e:
        print(f"Failed to download Tranco list: {e}", file=sys.stderr)

    # Try existing cache even if expired
    if os.path.exists(CACHE_FILE):
        return _parse_tranco_csv(CACHE_FILE)

    return {}


def _parse_tranco_csv(path: str) -> Dict[str, int]:
    """Parse Tranco CSV into a domain -> rank mapping."""
    ranks = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 2:
                    try:
                        rank = int(row[0])
                        domain = row[1].strip().lower()
                        ranks[domain] = rank
                    except (ValueError, IndexError):
                        continue
    except Exception as e:
        print(f"Error parsing Tranco list: {e}", file=sys.stderr)
    return ranks


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy."""
    if not text:
        return 0.0
    counter = Counter(text.lower())
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counter.values())


def check_domain(domain: str, tranco: Dict[str, int]) -> Dict:
    """Check a single domain's reputation."""
    domain = domain.lower().strip()
    trust_indicators = []
    risk_indicators = []

    # Tranco rank
    rank = tranco.get(domain, 0)
    # Also check parent domain (e.g., mail.google.com -> google.com)
    parts = domain.split(".")
    if not rank and len(parts) > 2:
        parent = ".".join(parts[-2:])
        rank = tranco.get(parent, 0)

    if rank:
        if rank <= 1000:
            trust_level = "high"
            trust_indicators.append(f"Tranco top 1K (rank #{rank})")
        elif rank <= 10000:
            trust_level = "high"
            trust_indicators.append(f"Tranco top 10K (rank #{rank})")
        elif rank <= 100000:
            trust_level = "medium"
            trust_indicators.append(f"Tranco top 100K (rank #{rank})")
        else:
            trust_level = "low"
            trust_indicators.append(f"Tranco rank #{rank}")
    else:
        trust_level = "unknown"

    # Trusted TLDs
    for tld in TRUSTED_TLDS:
        if domain.endswith(tld):
            trust_level = "high"
            trust_indicators.append(f"Trusted TLD: {tld}")
            break

    # Known company
    if domain in TRUSTED_COMPANIES:
        trust_level = "high"
        trust_indicators.append("Well-known company domain")

    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            risk_indicators.append(f"Suspicious TLD: {tld}")
            if trust_level == "unknown":
                trust_level = "low"
            break

    # Gibberish detection
    main_part = parts[-2] if len(parts) >= 2 else parts[0]
    if len(main_part) > 3:
        entropy = calculate_entropy(main_part)
        vowels = set("aeiou")
        vowel_count = sum(1 for c in main_part if c in vowels)
        vowel_ratio = vowel_count / len(main_part)

        is_gibberish = False
        if entropy > 2.3 and vowel_ratio < 0.25:
            is_gibberish = True
        elif entropy > 3.8:
            is_gibberish = True
        elif re.search(r"[bcdfghjklmnpqrstvwxz]{4,}", main_part):
            is_gibberish = True

        if is_gibberish:
            risk_indicators.append(f"Domain appears randomly generated (entropy: {entropy:.2f})")
            if trust_level in ("unknown", "low"):
                trust_level = "low"

    # Trust score (0-100)
    trust_score = 50  # default
    if trust_level == "high":
        trust_score = 90
    elif trust_level == "medium":
        trust_score = 65
    elif trust_level == "low":
        trust_score = 25
    elif trust_level == "unknown":
        trust_score = 40

    if risk_indicators:
        trust_score = max(0, trust_score - 15 * len(risk_indicators))

    return {
        "domain": domain,
        "trust_score": trust_score,
        "trust_level": trust_level,
        "tranco_rank": rank if rank else None,
        "trust_indicators": trust_indicators,
        "risk_indicators": risk_indicators,
    }


def main():
    parser = argparse.ArgumentParser(description="Check domain reputation")
    parser.add_argument("--domain", help="Single domain to check")
    parser.add_argument("--domains", help="Comma-separated domains")
    args = parser.parse_args()

    # Collect domains
    domains = []
    if args.domain:
        domains.append(args.domain)
    elif args.domains:
        domains = [d.strip() for d in args.domains.split(",") if d.strip()]
    else:
        domains = [line.strip() for line in sys.stdin if line.strip()]

    if not domains:
        print("Provide --domain, --domains, or pipe domains via stdin.", file=sys.stderr)
        sys.exit(1)

    # Load Tranco list
    tranco = load_tranco_list()

    # Check each domain
    results = [check_domain(d, tranco) for d in domains]
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
