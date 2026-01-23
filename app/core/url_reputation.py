"""
URL Reputation Checker
Integrates with external APIs to check URL/domain reputation:
- Google Safe Browsing API
- VirusTotal API
- PhishTank (via check)
"""

import os
import re
import asyncio
import hashlib
import logging
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse
from dataclasses import dataclass
from datetime import datetime, timedelta
import aiohttp

from app.core.url_validator import validate_url, sanitize_url_for_logging

logger = logging.getLogger(__name__)


@dataclass
class ReputationResult:
    """Result from reputation check"""
    source: str
    is_malicious: bool
    threat_type: Optional[str] = None
    confidence: float = 0.0
    details: Optional[str] = None
    reference_url: Optional[str] = None


@dataclass
class URLReputationReport:
    """Combined reputation report for a URL"""
    url: str
    domain: str
    is_malicious: bool
    risk_score: int  # 0-100
    threat_types: List[str]
    checks_performed: List[ReputationResult]
    recommendation: str


class URLReputationChecker:
    """
    Check URL reputation using multiple external APIs

    Supported APIs:
    - Google Safe Browsing API (free, 10k lookups/day)
    - VirusTotal API (free, 4 requests/minute)
    """

    # Cache to avoid repeated API calls (URL -> (result, timestamp))
    _cache: Dict[str, Tuple[URLReputationReport, datetime]] = {}
    CACHE_TTL = timedelta(hours=1)

    def __init__(self):
        self.google_api_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY', '')
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY', '')

        # Log API availability
        if self.google_api_key:
            logger.info("Google Safe Browsing API key configured")
        else:
            logger.warning("GOOGLE_SAFE_BROWSING_API_KEY not set - Google Safe Browsing checks disabled")

        if self.virustotal_api_key:
            logger.info("VirusTotal API key configured")
        else:
            logger.warning("VIRUSTOTAL_API_KEY not set - VirusTotal checks disabled")

    async def check_url(self, url: str) -> URLReputationReport:
        """
        Check URL reputation using all available APIs
        Returns combined report with risk assessment
        """
        # SSRF Protection: Validate URL before any processing
        is_safe, error_msg = validate_url(url)
        if not is_safe:
            logger.warning(f"SSRF blocked: {sanitize_url_for_logging(url)} - {error_msg}")
            return URLReputationReport(
                url=url,
                domain="blocked",
                is_malicious=True,
                risk_score=100,
                threat_types=["SSRF_BLOCKED"],
                checks_performed=[ReputationResult(
                    source="ssrf_protection",
                    is_malicious=True,
                    threat_type="SSRF_ATTEMPT",
                    confidence=1.0,
                    details=error_msg
                )],
                recommendation="URL blocked by SSRF protection. Internal/private URLs are not allowed."
            )

        # Check cache first
        cache_key = url.lower()
        if cache_key in self._cache:
            cached_result, timestamp = self._cache[cache_key]
            if datetime.now() - timestamp < self.CACHE_TTL:
                logger.debug(f"Cache hit for URL: {sanitize_url_for_logging(url)}")
                return cached_result

        # Extract domain
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
        except Exception:
            domain = url

        # Run all checks concurrently
        checks: List[ReputationResult] = []
        tasks = []

        if self.google_api_key:
            tasks.append(self._check_google_safe_browsing(url))

        if self.virustotal_api_key:
            tasks.append(self._check_virustotal(url))

        # Always run heuristic checks
        tasks.append(self._check_heuristics(url, domain))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, ReputationResult):
                    checks.append(result)
                elif isinstance(result, list):
                    checks.extend(result)
                elif isinstance(result, Exception):
                    logger.error(f"API check failed: {result}")

        # Build combined report
        report = self._build_report(url, domain, checks)

        # Cache the result
        self._cache[cache_key] = (report, datetime.now())

        return report

    async def _check_google_safe_browsing(self, url: str) -> Optional[ReputationResult]:
        """
        Check URL against Google Safe Browsing API
        Reference: https://developers.google.com/safe-browsing/v4
        """
        if not self.google_api_key:
            return None

        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.google_api_key}"

        payload = {
            "client": {
                "clientId": "secops-remediation-agent",
                "clientVersion": "2.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(api_url, json=payload, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()

                        if data.get("matches"):
                            match = data["matches"][0]
                            threat_type = match.get("threatType", "UNKNOWN")
                            return ReputationResult(
                                source="Google Safe Browsing",
                                is_malicious=True,
                                threat_type=threat_type,
                                confidence=0.95,
                                details=f"Detected as {threat_type}",
                                reference_url="https://safebrowsing.google.com/"
                            )
                        else:
                            return ReputationResult(
                                source="Google Safe Browsing",
                                is_malicious=False,
                                confidence=0.8,
                                details="No threats detected",
                                reference_url="https://safebrowsing.google.com/"
                            )
                    else:
                        logger.warning(f"Google Safe Browsing API error: {response.status}")
                        return None
        except Exception as e:
            logger.error(f"Google Safe Browsing check failed: {e}")
            return None

    async def _check_virustotal(self, url: str) -> Optional[ReputationResult]:
        """
        Check URL against VirusTotal API
        Reference: https://docs.virustotal.com/reference/overview

        Note: Free tier allows 4 requests/minute
        """
        if not self.virustotal_api_key:
            return None

        # VirusTotal uses base64-encoded URL without padding
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {
            "x-apikey": self.virustotal_api_key,
            "Accept": "application/json"
        }

        try:
            async with aiohttp.ClientSession() as session:
                # First, try to get existing analysis
                async with session.get(api_url, headers=headers, timeout=15) as response:
                    if response.status == 200:
                        data = await response.json()
                        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

                        malicious = stats.get("malicious", 0)
                        suspicious = stats.get("suspicious", 0)
                        total = sum(stats.values()) if stats else 0

                        if total > 0:
                            # Calculate detection ratio
                            detection_ratio = (malicious + suspicious) / total
                            is_malicious = malicious >= 3 or detection_ratio > 0.1

                            threat_types = []
                            if malicious > 0:
                                threat_types.append("malicious")
                            if suspicious > 0:
                                threat_types.append("suspicious")

                            return ReputationResult(
                                source="VirusTotal",
                                is_malicious=is_malicious,
                                threat_type=", ".join(threat_types) if threat_types else None,
                                confidence=min(0.95, detection_ratio + 0.5) if is_malicious else 0.7,
                                details=f"{malicious} malicious, {suspicious} suspicious out of {total} engines",
                                reference_url=f"https://www.virustotal.com/gui/url/{url_id}"
                            )

                    elif response.status == 404:
                        # URL not in database, submit for scanning
                        scan_url = "https://www.virustotal.com/api/v3/urls"
                        async with session.post(scan_url, headers=headers,
                                               data={"url": url}, timeout=15) as scan_response:
                            if scan_response.status == 200:
                                return ReputationResult(
                                    source="VirusTotal",
                                    is_malicious=False,
                                    confidence=0.3,
                                    details="URL submitted for analysis (not in database)",
                                    reference_url="https://www.virustotal.com/"
                                )

                    return None

        except Exception as e:
            logger.error(f"VirusTotal check failed: {e}")
            return None

    async def _check_heuristics(self, url: str, domain: str) -> List[ReputationResult]:
        """
        Perform heuristic checks (no API required)
        """
        results = []

        # Check for suspicious URL patterns
        suspicious_patterns = [
            (r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', 'IP address in URL'),
            (r'@', 'Credential injection attempt'),
            (r'\.php\?.*=', 'PHP parameter manipulation'),
            (r'(login|signin|verify|secure|account|update|confirm)', 'Credential harvesting keywords'),
            (r'[a-z0-9]{20,}\.', 'Long random subdomain'),
            (r'\.(ru|cn|tk|ml|ga|cf|gq)/', 'High-risk TLD'),
        ]

        for pattern, description in suspicious_patterns:
            if re.search(pattern, url.lower()):
                results.append(ReputationResult(
                    source="Heuristic Analysis",
                    is_malicious=True,
                    threat_type="suspicious_pattern",
                    confidence=0.6,
                    details=description,
                    reference_url="https://www.cisa.gov/secure-our-world/recognize-and-report-phishing"
                ))
                break

        # Check for URL redirection services used maliciously
        redirect_services = [
            'mg.cloudwick.com', 'email.mg.', 'links.', 'click.', 'track.',
            't.', 'r.', 'l.', 'go.', 'redirect.', 'redir.'
        ]

        if any(svc in domain for svc in redirect_services):
            results.append(ReputationResult(
                source="Heuristic Analysis",
                is_malicious=True,
                threat_type="email_tracking_redirect",
                confidence=0.7,
                details=f"Email tracking/redirect service detected: {domain}",
                reference_url="https://www.cisa.gov/secure-our-world/recognize-and-report-phishing"
            ))

        # Check for newly registered domain patterns (common in phishing)
        # These are domains that look auto-generated
        if self._looks_like_dga(domain):
            results.append(ReputationResult(
                source="Heuristic Analysis",
                is_malicious=True,
                threat_type="dga_domain",
                confidence=0.65,
                details="Domain appears to be auto-generated (potential DGA)",
                reference_url="https://www.ic3.gov/PSA/2020/PSA200406"
            ))

        # If no issues found, add a "clean" result
        if not results:
            results.append(ReputationResult(
                source="Heuristic Analysis",
                is_malicious=False,
                confidence=0.5,
                details="No suspicious patterns detected"
            ))

        return results

    def _looks_like_dga(self, domain: str) -> bool:
        """Check if domain looks like it was generated by a DGA"""
        parts = domain.split('.')
        if len(parts) < 2:
            return False

        main_part = parts[-2]

        # Check for random-looking strings
        if len(main_part) > 10:
            # High consonant ratio
            vowels = set('aeiou')
            vowel_count = sum(1 for c in main_part.lower() if c in vowels)
            if len(main_part) > 0 and vowel_count / len(main_part) < 0.2:
                return True

            # Many consecutive consonants
            if re.search(r'[bcdfghjklmnpqrstvwxz]{5,}', main_part.lower()):
                return True

        return False

    def _build_report(self, url: str, domain: str, checks: List[ReputationResult]) -> URLReputationReport:
        """Build combined reputation report"""

        # Determine if malicious based on all checks
        malicious_checks = [c for c in checks if c.is_malicious]

        # Calculate weighted risk score
        risk_score = 0
        threat_types = set()

        for check in checks:
            if check.is_malicious:
                # Weight by source reliability
                weight = {
                    "Google Safe Browsing": 40,
                    "VirusTotal": 35,
                    "Heuristic Analysis": 25
                }.get(check.source, 20)

                risk_score += int(weight * check.confidence)

                if check.threat_type:
                    threat_types.add(check.threat_type)

        # Cap at 100
        risk_score = min(100, risk_score)

        # Determine if malicious
        # - Any Google Safe Browsing hit = malicious
        # - VirusTotal with multiple detections = malicious
        # - Multiple heuristic flags = suspicious
        is_malicious = (
            any(c.source == "Google Safe Browsing" and c.is_malicious for c in checks) or
            any(c.source == "VirusTotal" and c.is_malicious and c.confidence > 0.7 for c in checks) or
            len(malicious_checks) >= 2 or
            risk_score >= 50
        )

        # Generate recommendation
        if is_malicious:
            if risk_score >= 70:
                recommendation = "HIGH RISK: This URL is flagged as malicious by security services. Do not visit."
            else:
                recommendation = "SUSPICIOUS: This URL shows signs of being malicious. Exercise extreme caution."
        else:
            recommendation = "No immediate threats detected, but always verify URLs from unknown senders."

        return URLReputationReport(
            url=url,
            domain=domain,
            is_malicious=is_malicious,
            risk_score=risk_score,
            threat_types=list(threat_types),
            checks_performed=checks,
            recommendation=recommendation
        )

    def get_api_status(self) -> Dict[str, bool]:
        """Return status of configured APIs"""
        return {
            "google_safe_browsing": bool(self.google_api_key),
            "virustotal": bool(self.virustotal_api_key),
            "heuristics": True  # Always available
        }


# Convenience functions
_checker: Optional[URLReputationChecker] = None


def get_checker() -> URLReputationChecker:
    """Get singleton instance of checker"""
    global _checker
    if _checker is None:
        _checker = URLReputationChecker()
    return _checker


async def check_url_reputation(url: str) -> Dict[str, Any]:
    """
    Check URL reputation and return dict for JSON serialization
    """
    checker = get_checker()
    report = await checker.check_url(url)

    return {
        "url": report.url,
        "domain": report.domain,
        "is_malicious": report.is_malicious,
        "risk_score": report.risk_score,
        "threat_types": report.threat_types,
        "recommendation": report.recommendation,
        "checks": [
            {
                "source": c.source,
                "is_malicious": c.is_malicious,
                "threat_type": c.threat_type,
                "confidence": c.confidence,
                "details": c.details,
                "reference_url": c.reference_url
            }
            for c in report.checks_performed
        ],
        "api_status": checker.get_api_status()
    }


async def check_urls_batch(urls: List[str]) -> List[Dict[str, Any]]:
    """Check multiple URLs concurrently"""
    tasks = [check_url_reputation(url) for url in urls[:10]]  # Limit to 10
    return await asyncio.gather(*tasks)
