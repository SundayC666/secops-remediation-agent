"""
Domain Checker
Checks domain registration and trust indicators using WHOIS and trusted registrar lists
"""

import re
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class DomainInfo:
    """Domain information from checks"""
    domain: str
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    age_days: Optional[int] = None
    is_trusted_registrar: bool = False
    is_new_domain: bool = False  # Less than 30 days old
    trust_indicators: List[str] = None
    risk_indicators: List[str] = None

    def __post_init__(self):
        if self.trust_indicators is None:
            self.trust_indicators = []
        if self.risk_indicators is None:
            self.risk_indicators = []


# Well-known trusted domain registrars
TRUSTED_REGISTRARS = [
    # Major registrars
    "godaddy",
    "namecheap",
    "cloudflare",
    "google domains",
    "aws",
    "amazon",
    "microsoft",
    "network solutions",
    "bluehost",
    "hostgator",
    "ionos",
    "hover",
    "name.com",
    "dynadot",
    "porkbun",
    "gandi",
    "enom",
    "register.com",
    "domain.com",
    # Enterprise/Corporate
    "markmonitor",
    "csc corporate domains",
    "safenames",
    "corporation service company",
]

# Well-known legitimate email service domains
LEGITIMATE_EMAIL_SERVICES = [
    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "yahoo.com",
    "icloud.com",
    "protonmail.com",
    "mail.com",
    "zoho.com",
    "fastmail.com",
    "tutanota.com",
]

# Well-known legitimate companies (major tech, banks, government)
TRUSTED_COMPANY_DOMAINS = {
    # Tech companies
    "google.com": "Google",
    "microsoft.com": "Microsoft",
    "apple.com": "Apple",
    "amazon.com": "Amazon",
    "meta.com": "Meta",
    "facebook.com": "Meta",
    "github.com": "GitHub",
    "linkedin.com": "LinkedIn",
    "twitter.com": "X/Twitter",
    "x.com": "X/Twitter",
    # Cloud providers
    "aws.amazon.com": "Amazon Web Services",
    "azure.microsoft.com": "Microsoft Azure",
    "cloud.google.com": "Google Cloud",
    "cloudflare.com": "Cloudflare",
    # Major banks (US)
    "chase.com": "JPMorgan Chase",
    "bankofamerica.com": "Bank of America",
    "wellsfargo.com": "Wells Fargo",
    "citi.com": "Citibank",
    # Major banks (International)
    "hsbc.com": "HSBC",
    "barclays.com": "Barclays",
    "ubs.com": "UBS",
    # Payment services
    "paypal.com": "PayPal",
    "stripe.com": "Stripe",
    "square.com": "Square",
    # Government (TW)
    "gov.tw": "Taiwan Government",
    "post.gov.tw": "Taiwan Post",
    "nhi.gov.tw": "Taiwan NHI",
    # Government (US)
    "gov": "US Government",
    "irs.gov": "IRS",
    "ssa.gov": "Social Security",
    # E-commerce
    "ebay.com": "eBay",
    "shopify.com": "Shopify",
    "etsy.com": "Etsy",
}

# Known suspicious/phishing-heavy registrars
SUSPICIOUS_REGISTRARS = [
    "freenom",
    "tokelau",
    "dot tk",
    ".tk",
    "anonymous",
]


class DomainChecker:
    """
    Checks domain registration information and trust indicators
    """

    def __init__(self):
        self.cache: Dict[str, DomainInfo] = {}

    def check_domain(self, domain: str) -> DomainInfo:
        """
        Check domain for trust/risk indicators

        This performs heuristic checks without actual WHOIS lookup
        (WHOIS requires external libraries/APIs)
        """
        # Normalize domain
        domain = domain.lower().strip()
        domain = re.sub(r'^(https?://)?', '', domain)
        domain = re.sub(r'^www\.', '', domain)
        domain = domain.split('/')[0]

        # Check cache
        if domain in self.cache:
            return self.cache[domain]

        info = DomainInfo(domain=domain)

        # Check if it's a known trusted domain
        self._check_trusted_domains(domain, info)

        # Check TLD reputation
        self._check_tld(domain, info)

        # Check domain age heuristics
        self._check_domain_patterns(domain, info)

        # Check for email service domains
        self._check_email_services(domain, info)

        # Cache result
        self.cache[domain] = info

        return info

    def _check_trusted_domains(self, domain: str, info: DomainInfo) -> None:
        """Check if domain is a known trusted company"""
        # Direct match
        if domain in TRUSTED_COMPANY_DOMAINS:
            info.trust_indicators.append(
                f"Verified domain: {TRUSTED_COMPANY_DOMAINS[domain]}"
            )
            info.is_trusted_registrar = True
            return

        # Check if it's a subdomain of a trusted domain
        for trusted, company in TRUSTED_COMPANY_DOMAINS.items():
            if domain.endswith(f".{trusted}"):
                info.trust_indicators.append(
                    f"Subdomain of verified company: {company}"
                )
                info.is_trusted_registrar = True
                return

        # Check government domains
        if domain.endswith(".gov") or domain.endswith(".gov.tw"):
            info.trust_indicators.append("Government domain")
            info.is_trusted_registrar = True
        elif domain.endswith(".edu") or domain.endswith(".edu.tw"):
            info.trust_indicators.append("Educational institution")
            info.is_trusted_registrar = True

    def _check_tld(self, domain: str, info: DomainInfo) -> None:
        """Check TLD reputation"""
        suspicious_tlds = [
            ".tk", ".ml", ".ga", ".cf", ".gq",  # Free domains
            ".top", ".xyz", ".work", ".click",  # High spam TLDs
            ".vip", ".icu", ".buzz", ".monster",  # Newer suspicious TLDs
            ".loan", ".date", ".racing", ".stream",  # Known phishing TLDs
        ]

        low_trust_tlds = [
            ".info", ".biz", ".online", ".site", ".website",
            ".space", ".link", ".club", ".fun", ".live"
        ]

        high_trust_tlds = [
            ".com", ".org", ".net", ".edu", ".gov",
            ".io", ".co", ".app", ".dev"
        ]

        tld = "." + domain.split(".")[-1] if "." in domain else ""

        for s_tld in suspicious_tlds:
            if domain.endswith(s_tld):
                info.risk_indicators.append(
                    f"High-risk TLD ({s_tld}) commonly used for phishing"
                )
                return

        for l_tld in low_trust_tlds:
            if domain.endswith(l_tld):
                info.risk_indicators.append(
                    f"Low-trust TLD ({l_tld}) - verify legitimacy"
                )
                return

        for h_tld in high_trust_tlds:
            if domain.endswith(h_tld):
                info.trust_indicators.append(f"Standard TLD ({h_tld})")
                return

    def _check_domain_patterns(self, domain: str, info: DomainInfo) -> None:
        """Check for suspicious domain patterns"""
        # Check for typosquatting of major brands
        brand_typos = {
            "googl": "google",
            "gogle": "google",
            "goog1e": "google",
            "g00gle": "google",
            "micros0ft": "microsoft",
            "mircosoft": "microsoft",
            "microsooft": "microsoft",
            "amaz0n": "amazon",
            "arnazon": "amazon",
            "arnezon": "amazon",
            "paypa1": "paypal",
            "payp4l": "paypal",
            "app1e": "apple",
            "faceb00k": "facebook",
            "lnstagram": "instagram",
        }

        domain_lower = domain.lower()
        for typo, brand in brand_typos.items():
            if typo in domain_lower and brand not in domain_lower:
                info.risk_indicators.append(
                    f"Possible typosquatting of {brand}"
                )

        # Check for excessive hyphens
        if domain.count("-") > 2:
            info.risk_indicators.append(
                "Multiple hyphens - common in phishing domains"
            )

        # Check for numeric substitutions
        if re.search(r'[a-z][0-9][a-z]', domain_lower):
            info.risk_indicators.append(
                "Letter-number substitution pattern"
            )

        # Check for very long subdomains (often used to hide real domain)
        parts = domain.split(".")
        if len(parts) > 3:
            info.risk_indicators.append(
                "Multiple subdomains - may be hiding actual domain"
            )

        # Check for random-looking domains (high entropy)
        if len(parts) > 0:
            main_domain = parts[-2] if len(parts) > 1 else parts[0]
            if len(main_domain) > 15 and not any(
                word in main_domain
                for word in ["cloud", "service", "online", "digital", "network"]
            ):
                # Check if it looks random (consonant clusters, etc.)
                consonant_clusters = len(re.findall(r'[bcdfghjklmnpqrstvwxyz]{4,}', main_domain))
                if consonant_clusters > 0:
                    info.risk_indicators.append(
                        "Random-looking domain name"
                    )

    def _check_email_services(self, domain: str, info: DomainInfo) -> None:
        """Check if domain is a legitimate email service"""
        if domain in LEGITIMATE_EMAIL_SERVICES:
            info.trust_indicators.append(
                "Legitimate email service provider"
            )
            info.is_trusted_registrar = True

    def get_domain_trust_score(self, domain: str) -> Dict[str, Any]:
        """
        Get a trust score for a domain (0-100)

        Returns dict with score and breakdown
        """
        info = self.check_domain(domain)

        score = 50  # Start neutral

        # Trusted indicators add points
        score += len(info.trust_indicators) * 15

        # Risk indicators subtract points
        score -= len(info.risk_indicators) * 20

        # Known trusted domain gets high score
        if info.is_trusted_registrar:
            score = max(score, 80)

        # Clamp score
        score = max(0, min(100, score))

        return {
            "domain": domain,
            "trust_score": score,
            "trust_level": "high" if score >= 70 else "medium" if score >= 40 else "low",
            "trust_indicators": info.trust_indicators,
            "risk_indicators": info.risk_indicators,
            "is_known_trusted": info.is_trusted_registrar
        }


# Singleton instance
_domain_checker: Optional[DomainChecker] = None


def get_domain_checker() -> DomainChecker:
    """Get or create domain checker instance"""
    global _domain_checker
    if _domain_checker is None:
        _domain_checker = DomainChecker()
    return _domain_checker
