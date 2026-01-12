"""
Automatic Version Tracker Service
Provides latest OS/software versions for quick search buttons

Strategy:
- Uses curated known versions as the primary source (most reliable)
- Caches results to minimize overhead
- Provides easy manual update via config file or API
- No dependency on external APIs for version info (more stable)

The KNOWN_VERSIONS dict can be updated:
1. Manually edit this file
2. Via the /api/versions/refresh endpoint with version data
3. Via the version_cache.json file
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

# Cache file location
CACHE_FILE = Path(__file__).parent.parent.parent / "data" / "version_cache.json"

# Curated known latest versions
# This is the authoritative source - update this when new versions are released
KNOWN_VERSIONS = {
    "macos": {
        "name": "macOS",
        "icon": "fab fa-apple",
        "css_class": "macos",
        "versions": [
            {"version": "15", "codename": "Sequoia", "query": "macOS 15", "display": "macOS 15", "year": 2024},
            {"version": "14", "codename": "Sonoma", "query": "macOS 14", "display": "macOS 14", "year": 2023},
        ]
    },
    "windows": {
        "name": "Windows",
        "icon": "fab fa-windows",
        "css_class": "windows",
        "versions": [
            {"version": "11", "query": "Windows 11", "display": "Windows 11", "year": 2021},
            {"version": "10", "query": "Windows 10", "display": "Windows 10", "year": 2015},
        ]
    },
    "ubuntu": {
        "name": "Ubuntu",
        "icon": "fab fa-ubuntu",
        "css_class": "linux",
        "versions": [
            {"version": "24.04", "codename": "Noble", "query": "Ubuntu 24", "display": "Ubuntu 24", "year": 2024},
            {"version": "22.04", "codename": "Jammy", "query": "Ubuntu 22", "display": "Ubuntu 22", "year": 2022},
        ]
    },
    "ios": {
        "name": "iOS",
        "icon": "fab fa-apple",
        "css_class": "ios",
        "versions": [
            {"version": "26", "query": "iOS 26", "display": "iOS 26", "year": 2026},
            {"version": "18", "query": "iOS 18", "display": "iOS 18", "year": 2024},
        ]
    },
    "android": {
        "name": "Android",
        "icon": "fab fa-android",
        "css_class": "android",
        "versions": [
            {"version": "15", "query": "Android 15", "display": "Android 15", "year": 2024},
            {"version": "14", "query": "Android 14", "display": "Android 14", "year": 2023},
        ]
    },
    "chrome": {
        "name": "Chrome",
        "icon": "fab fa-chrome",
        "css_class": "browser",
        "versions": [
            {"version": "latest", "query": "Chrome", "display": "Chrome"},
        ]
    },
    "firefox": {
        "name": "Firefox",
        "icon": "fab fa-firefox-browser",
        "css_class": "browser",
        "versions": [
            {"version": "latest", "query": "Firefox", "display": "Firefox"},
        ]
    },
    "safari": {
        "name": "Safari",
        "icon": "fab fa-safari",
        "css_class": "browser",
        "versions": [
            {"version": "latest", "query": "Safari", "display": "Safari"},
        ]
    },
}


class VersionTracker:
    """Tracks latest software versions for quick search buttons"""

    def __init__(self):
        self.versions: Dict[str, Any] = {}
        self.last_updated: Optional[datetime] = None
        self._load_versions()

    def _load_versions(self):
        """Load versions from cache file or use defaults"""
        try:
            if CACHE_FILE.exists():
                with open(CACHE_FILE, 'r') as f:
                    data = json.load(f)
                    if 'versions' in data:
                        self.versions = data['versions']
                        self.last_updated = datetime.fromisoformat(data.get('updated', datetime.now().isoformat()))
                        logger.info(f"Loaded {len(self.versions)} products from version cache")
                        return
        except Exception as e:
            logger.warning(f"Failed to load version cache: {e}")

        # Use default known versions
        self.versions = KNOWN_VERSIONS.copy()
        self.last_updated = datetime.now()
        self._save_cache()
        logger.info("Using default known versions")

    def _save_cache(self):
        """Save current versions to cache file"""
        try:
            CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(CACHE_FILE, 'w') as f:
                json.dump({
                    'versions': self.versions,
                    'updated': self.last_updated.isoformat() if self.last_updated else datetime.now().isoformat(),
                    'source': 'curated'
                }, f, indent=2)
            logger.info("Saved version cache")
        except Exception as e:
            logger.warning(f"Failed to save version cache: {e}")

    async def update_versions(self, force: bool = False) -> Dict[str, Any]:
        """
        Get current versions.

        If force=True, reload from cache file (useful if manually edited)
        """
        if force:
            self._load_versions()
        return self.versions

    async def set_version(self, product: str, versions: List[Dict]) -> bool:
        """
        Update versions for a specific product.

        Args:
            product: Product key (e.g., 'macos', 'ios')
            versions: List of version dicts with query, display, version keys

        Returns:
            True if successful
        """
        if product not in self.versions:
            logger.warning(f"Unknown product: {product}")
            return False

        # Validate version data
        for v in versions:
            if 'query' not in v or 'display' not in v:
                logger.warning(f"Invalid version data: {v}")
                return False

        self.versions[product]['versions'] = versions
        self.last_updated = datetime.now()
        self._save_cache()
        logger.info(f"Updated versions for {product}")
        return True

    async def get_quick_buttons(self) -> List[Dict]:
        """Get formatted data for quick search buttons"""
        buttons = []
        # Order: macOS, Windows, Ubuntu, iOS, Android, Browsers
        order = ["macos", "windows", "ubuntu", "ios", "android", "chrome", "firefox", "safari"]

        for product_key in order:
            product = self.versions.get(product_key, {})
            for ver in product.get("versions", [])[:2]:  # Max 2 versions per product
                buttons.append({
                    "label": ver.get("display", ver.get("query", "")),
                    "query": ver.get("query", ""),
                    "icon": product.get("icon", "fas fa-desktop"),
                    "css_class": product.get("css_class", ""),
                })

        return buttons

    def get_status(self) -> Dict:
        """Get tracker status information"""
        return {
            "products": len(self.versions),
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
            "cache_file": str(CACHE_FILE),
            "cache_exists": CACHE_FILE.exists()
        }


# Singleton instance
_tracker: Optional[VersionTracker] = None


def get_version_tracker() -> VersionTracker:
    """Get the singleton VersionTracker instance"""
    global _tracker
    if _tracker is None:
        _tracker = VersionTracker()
    return _tracker
