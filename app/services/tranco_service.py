"""
Tranco List Service
Downloads and caches the Tranco top domains list for domain reputation scoring.

Tranco List: https://tranco-list.eu/
- Academic-sourced top 1 million domains
- Updated daily
- Free to use, no API key required
- CC BY-NC-SA 4.0 License

Citation:
Le Pochat, V., Van Goethem, T., Tajalizadehkhoob, S., Korczyński, M., & Joosen, W. (2019).
Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation.
Proceedings of the 26th Annual Network and Distributed System Security Symposium (NDSS 2019).
https://doi.org/10.14722/ndss.2019.23386
"""

import os
import csv
import io
import zipfile
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Set
import requests

logger = logging.getLogger(__name__)

# Configuration
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
CACHE_DIR = Path(__file__).parent.parent.parent / "data" / "tranco"
CACHE_FILE = CACHE_DIR / "top-domains.csv"
CACHE_META_FILE = CACHE_DIR / "meta.txt"
CACHE_DURATION_DAYS = 7  # Update weekly
TOP_N_DOMAINS = 10000  # Only load top N domains for memory efficiency


class TrancoService:
    """
    Service for managing Tranco domain list.
    Provides domain trust scoring based on global popularity ranking.
    """

    _instance = None
    _domains: Dict[str, int] = {}  # domain -> rank
    _domain_set: Set[str] = set()
    _loaded = False
    _last_update: Optional[datetime] = None
    _data_source: str = "offline_fallback"  # "tranco_list" or "offline_fallback"

    def __new__(cls):
        """Singleton pattern to avoid multiple downloads"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._loaded:
            self._ensure_cache_dir()
            self._load_domains()

    def _ensure_cache_dir(self):
        """Create cache directory if it doesn't exist"""
        CACHE_DIR.mkdir(parents=True, exist_ok=True)

    def _is_cache_valid(self) -> bool:
        """Check if local cache is still valid"""
        if not CACHE_FILE.exists() or not CACHE_META_FILE.exists():
            return False

        try:
            with open(CACHE_META_FILE, 'r') as f:
                last_update_str = f.read().strip()
                last_update = datetime.fromisoformat(last_update_str)
                return datetime.now() - last_update < timedelta(days=CACHE_DURATION_DAYS)
        except (ValueError, IOError):
            return False

    def _download_tranco_list(self) -> bool:
        """Download fresh Tranco list from server"""
        try:
            logger.info("Downloading Tranco list from %s", TRANCO_URL)
            response = requests.get(TRANCO_URL, timeout=30)
            response.raise_for_status()

            # Extract CSV from ZIP
            with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                # Find the CSV file in the archive
                csv_name = [n for n in z.namelist() if n.endswith('.csv')][0]
                with z.open(csv_name) as csv_file:
                    content = csv_file.read().decode('utf-8')

            # Save to cache
            with open(CACHE_FILE, 'w', encoding='utf-8') as f:
                f.write(content)

            # Update metadata
            with open(CACHE_META_FILE, 'w') as f:
                f.write(datetime.now().isoformat())

            logger.info("Tranco list downloaded successfully")
            self._data_source = "tranco_list"
            return True

        except Exception as e:
            logger.warning("Failed to download Tranco list: %s", e)
            return False

    def _load_domains(self):
        """Load domains from cache or download fresh"""
        # Try to update if cache is expired
        if not self._is_cache_valid():
            if not self._download_tranco_list():
                logger.warning("Using offline fallback - Tranco list unavailable")
                self._load_offline_fallback()
                return

        # Load from cache
        if CACHE_FILE.exists():
            try:
                self._domains = {}
                self._domain_set = set()
                with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                    reader = csv.reader(f)
                    for row in reader:
                        if len(row) >= 2:
                            rank = int(row[0])
                            domain = row[1].lower().strip()
                            if rank <= TOP_N_DOMAINS:
                                self._domains[domain] = rank
                                self._domain_set.add(domain)
                            else:
                                break  # Stop after TOP_N_DOMAINS

                self._loaded = True
                self._data_source = "tranco_list"
                logger.info("Loaded %d domains from Tranco list", len(self._domains))
            except Exception as e:
                logger.error("Failed to load Tranco cache: %s", e)
                self._load_offline_fallback()
        else:
            self._load_offline_fallback()

    def _load_offline_fallback(self):
        """Load built-in offline fallback list"""
        # Hardcoded list of top domains as fallback
        fallback_domains = [
            # Top 100 most trusted domains (curated list)
            "google.com", "youtube.com", "facebook.com", "twitter.com", "instagram.com",
            "linkedin.com", "microsoft.com", "apple.com", "amazon.com", "netflix.com",
            "github.com", "stackoverflow.com", "wikipedia.org", "reddit.com", "yahoo.com",
            "whatsapp.com", "tiktok.com", "zoom.us", "office.com", "live.com",
            "bing.com", "duckduckgo.com", "cloudflare.com", "wordpress.com", "shopify.com",
            "paypal.com", "stripe.com", "slack.com", "discord.com", "twitch.tv",
            "spotify.com", "dropbox.com", "adobe.com", "salesforce.com", "oracle.com",
            "ibm.com", "intel.com", "nvidia.com", "amd.com", "cisco.com",
            "aws.amazon.com", "azure.microsoft.com", "cloud.google.com",
            "outlook.com", "gmail.com", "icloud.com", "protonmail.com",
            "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com",
            "uber.com", "lyft.com", "airbnb.com", "booking.com", "expedia.com",
            "nytimes.com", "bbc.com", "cnn.com", "reuters.com", "bloomberg.com",
            "github.io", "githubusercontent.com", "npmjs.com", "pypi.org",
            "medium.com", "substack.com", "notion.so", "figma.com", "canva.com",
            "zoom.us", "webex.com", "gotomeeting.com", "teams.microsoft.com",
            "atlassian.com", "jira.com", "confluence.com", "trello.com",
            "hubspot.com", "mailchimp.com", "sendgrid.com", "constantcontact.com",
            "indeed.com", "glassdoor.com", "monster.com", "ziprecruiter.com",
            "coursera.org", "udemy.com", "edx.org", "khanacademy.org",
            # Recruiting/Assessment platforms
            "codesignal.com", "hackerrank.com", "leetcode.com", "codility.com",
            "greenhouse.io", "lever.co", "workday.com", "icims.com",
            # Cloud/CDN providers
            "cloudfront.net", "akamaihd.net", "fastly.net", "cdn.jsdelivr.net",
            # Email tracking (legitimate)
            "awstrack.me", "amazonses.com", "sendgrid.net", "list-manage.com",
        ]

        self._domains = {domain: idx + 1 for idx, domain in enumerate(fallback_domains)}
        self._domain_set = set(fallback_domains)
        self._loaded = True
        self._data_source = "offline_fallback"
        logger.info("Loaded %d domains from offline fallback", len(self._domains))

    def get_domain_rank(self, domain: str) -> Optional[int]:
        """
        Get the Tranco rank of a domain.
        Returns None if domain is not in the list.

        Lower rank = more popular/trusted
        """
        domain = domain.lower().strip()

        # Direct match
        if domain in self._domains:
            return self._domains[domain]

        # Try without www prefix
        if domain.startswith("www."):
            base_domain = domain[4:]
            if base_domain in self._domains:
                return self._domains[base_domain]

        # Try parent domain (e.g., mail.google.com -> google.com)
        parts = domain.split(".")
        if len(parts) > 2:
            parent = ".".join(parts[-2:])
            if parent in self._domains:
                return self._domains[parent]

        return None

    def is_popular_domain(self, domain: str, threshold: int = 10000) -> bool:
        """Check if domain is in top N popular domains"""
        rank = self.get_domain_rank(domain)
        return rank is not None and rank <= threshold

    def get_trust_score(self, domain: str) -> tuple[str, int]:
        """
        Get trust level and score for a domain.

        Returns:
            (trust_level, confidence_score)
            trust_level: "high", "medium", "low", "unknown"
            confidence_score: 0-100
        """
        rank = self.get_domain_rank(domain)

        if rank is None:
            return "unknown", 0

        if rank <= 100:
            return "high", 95
        elif rank <= 500:
            return "high", 90
        elif rank <= 1000:
            return "high", 85
        elif rank <= 5000:
            return "medium", 70
        elif rank <= 10000:
            return "medium", 60
        else:
            return "low", 40

    def get_data_source(self) -> str:
        """Return current data source: 'tranco_list' or 'offline_fallback'"""
        return self._data_source

    def get_data_source_display(self) -> dict:
        """Return data source info for display in UI"""
        if self._data_source == "tranco_list":
            return {
                "source": "Tranco List",
                "description": "Academic top domains list (tranco-list.eu)",
                "icon": "globe",
                "status": "online"
            }
        else:
            return {
                "source": "Offline Fallback",
                "description": "Built-in trusted domains list",
                "icon": "database",
                "status": "offline"
            }

    def force_update(self) -> bool:
        """Force update the Tranco list"""
        return self._download_tranco_list()


# Singleton instance
_tranco_service: Optional[TrancoService] = None


def get_tranco_service() -> TrancoService:
    """Get the singleton Tranco service instance"""
    global _tranco_service
    if _tranco_service is None:
        _tranco_service = TrancoService()
    return _tranco_service
