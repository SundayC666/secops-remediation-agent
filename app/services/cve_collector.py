"""
CVE Data Collector
Fetches CVE data from multiple sources:
- CIRCL CVE API (primary - most up-to-date)
- NIST NVD API (fallback)
- CISA KEV catalog (for exploited vulnerabilities)
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


class CVEDataCollector:
    """
    Collects CVE data from multiple sources:
    - CIRCL CVE API (primary - has latest CVEs including 2026)
    - NIST NVD (National Vulnerability Database) - fallback
    - CISA KEV (Known Exploited Vulnerabilities)
    """

    # CIRCL CVE API - new Vulnerability-Lookup API (has the latest CVEs)
    CIRCL_API_URL = "https://vulnerability.circl.lu/api"
    # NVD API as fallback
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self):
        self.cache_file = Path(settings.CVE_CACHE_FILE)
        self.cache_ttl = timedelta(hours=settings.CVE_CACHE_TTL_HOURS)
        self.lookback_days = settings.CVE_LOOKBACK_DAYS
        self.max_results = settings.CVE_MAX_RESULTS
        self.nvd_api_key = settings.NVD_API_KEY

        # Ensure cache directory exists
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)

    async def fetch_all(self, force_refresh: bool = False) -> List[Dict[str, Any]]:
        """
        Fetch CVE data from all sources

        Args:
            force_refresh: If True, bypass cache and fetch fresh data

        Returns:
            List of CVE records with enriched data
        """
        # Check cache first
        if not force_refresh and self._is_cache_valid():
            logger.info("Loading CVE data from cache")
            return self._load_cache()

        logger.info("Fetching fresh CVE data from sources...")

        # Fetch from both sources concurrently
        nvd_task = self._fetch_nvd_cves()
        kev_task = self._fetch_cisa_kev()

        nvd_cves, kev_cves = await asyncio.gather(nvd_task, kev_task)

        # Create KEV lookup set for quick checking
        kev_ids = {cve["cveID"] for cve in kev_cves}

        # Process and enrich CVE data
        processed_cves = []
        for cve in nvd_cves:
            processed = self._process_nvd_cve(cve)
            if processed:
                # Mark if in KEV (actively exploited)
                processed["is_exploited"] = processed["cve_id"] in kev_ids
                if processed["is_exploited"]:
                    # Add KEV details
                    kev_data = next(
                        (k for k in kev_cves if k["cveID"] == processed["cve_id"]),
                        None
                    )
                    if kev_data:
                        processed["kev_due_date"] = kev_data.get("dueDate")
                        processed["kev_notes"] = kev_data.get("notes")
                processed_cves.append(processed)

        # Sort by severity and date
        processed_cves.sort(
            key=lambda x: (
                -self._severity_score(x.get("severity", "UNKNOWN")),
                x.get("published_date", "")
            ),
            reverse=True
        )

        # Limit results
        processed_cves = processed_cves[:self.max_results]

        # Save to cache
        self._save_cache(processed_cves)

        logger.info(f"Collected {len(processed_cves)} CVEs ({sum(1 for c in processed_cves if c.get('is_exploited'))} actively exploited)")

        return processed_cves

    async def _fetch_nvd_cves(self) -> List[Dict[str, Any]]:
        """Fetch CVEs from NIST NVD API"""
        cves = []
        # Use lastModified date range to get recently updated CVEs
        # NVD API has a 120-day maximum range limit
        end_date = datetime.now()
        start_date = end_date - timedelta(days=min(self.lookback_days, 120))

        params = {
            "lastModStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
            "lastModEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
            "resultsPerPage": 100,
            "startIndex": 0
        }

        headers = {}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                while True:
                    logger.debug(f"Fetching NVD CVEs (offset: {params['startIndex']})")

                    response = await client.get(
                        self.NVD_API_URL,
                        params=params,
                        headers=headers
                    )
                    response.raise_for_status()
                    data = response.json()

                    vulnerabilities = data.get("vulnerabilities", [])
                    if not vulnerabilities:
                        break

                    cves.extend(vulnerabilities)

                    # Check if we have more pages
                    total = data.get("totalResults", 0)
                    if params["startIndex"] + len(vulnerabilities) >= total:
                        break

                    params["startIndex"] += len(vulnerabilities)

                    # Rate limiting (NVD allows 5 requests per 30 seconds without API key)
                    if not self.nvd_api_key:
                        await asyncio.sleep(6)
                    else:
                        await asyncio.sleep(0.6)

                    # Limit total results
                    if len(cves) >= self.max_results * 2:
                        break

        except httpx.HTTPError as e:
            logger.error(f"Error fetching NVD CVEs: {e}")

        return cves

    async def fetch_by_keyword(self, keyword: str, limit: int = 50, years: int = 5) -> List[Dict[str, Any]]:
        """
        Fetch CVEs by keyword search (e.g., 'apple', 'macos', 'windows')

        Uses new CIRCL Vulnerability-Lookup API for search - has the most up-to-date CVEs.
        Falls back to NVD API if CIRCL fails.

        Args:
            keyword: Search keyword (vendor/product)
            limit: Maximum number of results
            years: Only fetch CVEs from the last N years (default: 5)
        """
        cves = []
        seen_cve_ids = set()

        # Calculate cutoff year for filtering
        current_year = datetime.now().year
        min_year = current_year - years

        # Normalize and generate keyword variants to handle user input flexibility
        def generate_keyword_variants(raw_keyword: str) -> list:
            """Generate multiple search variants from user input to handle flexible formats"""
            variants = set()
            kw = raw_keyword.lower().strip()
            kw = " ".join(kw.split())  # Normalize spaces

            # Original (cleaned)
            variants.add(kw)

            # No spaces version: "iPad OS" -> "ipados"
            variants.add(kw.replace(" ", ""))

            # Underscore version: "iPad OS" -> "ipad_os"
            variants.add(kw.replace(" ", "_"))

            # Dash version: "visual studio" -> "visual-studio"
            variants.add(kw.replace(" ", "-"))

            # Remove common version patterns: "windows 11" -> "windows", "ios 18" -> "ios"
            import re
            no_version = re.sub(r'\s*\d+(\.\d+)*\s*$', '', kw).strip()
            if no_version and no_version != kw:
                variants.add(no_version)
                variants.add(no_version.replace(" ", ""))

            # Handle common abbreviations
            abbrev_map = {
                "win": "windows", "win10": "windows_10", "win11": "windows_11",
                "mac": "macos", "osx": "macos", "os x": "macos",
                "ipad os": "ipados", "iphone os": "ios",
                "k8s": "kubernetes", "postgres": "postgresql", "mongo": "mongodb",
                "js": "javascript", "ts": "typescript", "py": "python",
                "node": "nodejs", "react": "react", "vue": "vuejs", "ng": "angular",
            }
            if kw in abbrev_map:
                variants.add(abbrev_map[kw])

            return list(variants)

        kw_variants = generate_keyword_variants(keyword)
        logger.debug(f"Generated keyword variants: {kw_variants}")

        # Vendor -> their main products mapping (for vendor name searches)
        VENDOR_PRODUCTS = {
            "adobe": ["acrobat", "reader", "photoshop", "flash_player", "creative_cloud"],
            "apple": ["macos", "ios", "safari", "ipados", "watchos"],
            "microsoft": ["windows", "office", "edge", "exchange", "azure"],
            "google": ["chrome", "android", "chromium"],
            "mozilla": ["firefox", "thunderbird"],
            "oracle": ["java", "mysql", "database"],
            "cisco": ["ios", "webex", "anyconnect"],
            "vmware": ["esxi", "vcenter", "workstation"],
            "linux": ["kernel"],
            "redhat": ["enterprise_linux"],
        }

        # Common vendors to try for product searches
        COMMON_VENDORS = list(VENDOR_PRODUCTS.keys())

        # Build search URLs - try multiple strategies
        search_urls = []

        for kw in kw_variants:
            parts = kw.split()

            if len(parts) >= 2:
                # Multi-word: first word might be vendor
                vendor = parts[0]
                product = parts[1]
                search_urls.append(f"{self.CIRCL_API_URL}/vulnerability/search/{vendor}/{product}")
                search_urls.append(f"{self.CIRCL_API_URL}/vulnerability/search/{vendor}/{'_'.join(parts[1:])}")
            else:
                # Single word
                if kw in VENDOR_PRODUCTS:
                    # It's a VENDOR name (adobe, apple, etc.) - search their products
                    for product in VENDOR_PRODUCTS[kw]:
                        search_urls.append(f"{self.CIRCL_API_URL}/vulnerability/search/{kw}/{product}")
                else:
                    # It's a PRODUCT name - try vendor/product and product/product
                    # 1. Try as product/product (nginx/nginx, wordpress/wordpress, etc.)
                    search_urls.append(f"{self.CIRCL_API_URL}/vulnerability/search/{kw}/{kw}")
                    # 2. Try under common vendors (apple/ipados, microsoft/windows, etc.)
                    for vendor in COMMON_VENDORS:
                        search_urls.append(f"{self.CIRCL_API_URL}/vulnerability/search/{vendor}/{kw}")

        # Remove duplicates while preserving order
        seen = set()
        unique_urls = []
        for url in search_urls:
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)
        search_urls = unique_urls[:30]  # Limit requests

        logger.info(f"Fetching CVEs from CIRCL API for: {keyword} (last {years} years)")

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                for search_url in search_urls:
                    try:
                        response = await client.get(search_url)
                        if response.status_code != 200:
                            continue
                        data = response.json()

                        # New CIRCL API returns results in format: {"results": {"fkie_nvd": [...], "cvelistv5": [...]}}
                        results = data.get("results", {})

                        # Collect CVEs from all sources
                        for source_name, source_results in results.items():
                            for item in source_results[:limit * 3]:
                                if isinstance(item, list) and len(item) >= 2:
                                    cve_id = item[0].upper()
                                    # Remove source prefix if present (e.g., "fkie_cve-2025-..." -> "CVE-2025-...")
                                    if cve_id.startswith("FKIE_"):
                                        cve_id = cve_id[5:]
                                    if not cve_id.startswith("CVE-"):
                                        cve_id = f"CVE-{cve_id.split('CVE-')[-1]}" if "CVE-" in cve_id else cve_id

                                    # Skip duplicates
                                    if cve_id in seen_cve_ids:
                                        continue
                                    seen_cve_ids.add(cve_id)

                                    cve_data = item[1]

                                    # Filter by year from CVE ID (CVE-YYYY-XXXXX)
                                    try:
                                        cve_year = int(cve_id.split('-')[1])
                                        if cve_year < min_year:
                                            continue  # Skip CVEs older than cutoff
                                    except (IndexError, ValueError):
                                        pass  # If can't parse year, include it

                                    # Convert to our standard format
                                    cve_record = self._convert_new_circl_to_standard(cve_id, cve_data)
                                    if cve_record:
                                        cves.append(cve_record)

                        # Stop if we have enough results
                        if len(cves) >= limit * 2:
                            break

                    except Exception as e:
                        logger.debug(f"CIRCL search failed for {search_url}: {e}")
                        continue

                logger.info(f"Found {len(cves)} CVEs from CIRCL API for {keyword} (after year filter)")

        except httpx.HTTPError as e:
            logger.warning(f"CIRCL API error for '{keyword}': {e}, falling back to NVD")
            return await self._fetch_by_keyword_nvd(keyword, limit, years)
        except Exception as e:
            logger.error(f"Error fetching CVEs for keyword '{keyword}': {e}")
            # Try NVD as fallback
            return await self._fetch_by_keyword_nvd(keyword, limit, years)

        # If no results from CIRCL, try NVD
        if not cves:
            logger.info(f"No CIRCL results for {keyword}, trying NVD")
            return await self._fetch_by_keyword_nvd(keyword, limit, years)

        # Process the CVEs
        processed = []
        kev_cves = await self._fetch_cisa_kev()
        kev_ids = {cve["cveID"] for cve in kev_cves}

        for cve in cves:
            p = self._process_nvd_cve(cve)
            if p:
                p["is_exploited"] = p["cve_id"] in kev_ids
                processed.append(p)

        # Sort by date (newest first) then by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        processed.sort(
            key=lambda x: (
                x.get("published_date", "0000-00-00"),  # Date descending (newer first)
                severity_order.get(x.get("severity", "UNKNOWN"), 4)  # Then by severity
            ),
            reverse=True
        )

        # Limit results after sorting
        processed = processed[:limit]

        logger.info(f"Found {len(processed)} CVEs for keyword: {keyword}")
        return processed

    def _convert_new_circl_to_standard(self, cve_id: str, cve_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Convert new CIRCL Vulnerability-Lookup API format to our standard NVD-like format.
        Handles both CVE 5.0/5.1 format (containers.cna) and older format.
        """
        try:
            description = ""
            severity = "UNKNOWN"
            cvss_score = None
            published = ""
            references = []

            # CVE 5.0/5.1 format: data is in containers.cna
            containers = cve_data.get("containers", {})
            cna = containers.get("cna", {})

            if cna:
                # CVE 5.0/5.1 format
                descriptions = cna.get("descriptions", [])
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break
                if not description and descriptions:
                    description = descriptions[0].get("value", "")

                # Get CVSS from metrics in cna
                metrics_list = cna.get("metrics", [])
                for metric in metrics_list:
                    if "cvssV3_1" in metric:
                        cvss = metric["cvssV3_1"]
                        severity = cvss.get("baseSeverity", "UNKNOWN")
                        cvss_score = cvss.get("baseScore")
                        break
                    elif "cvssV3_0" in metric:
                        cvss = metric["cvssV3_0"]
                        severity = cvss.get("baseSeverity", "UNKNOWN")
                        cvss_score = cvss.get("baseScore")
                        break

                # Get references
                references = cna.get("references", [])

                # Get published date from metadata
                metadata = cve_data.get("cveMetadata", {})
                published = metadata.get("datePublished", "")
            else:
                # Older format - descriptions at top level
                descriptions = cve_data.get("descriptions", [])
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break
                if not description and descriptions:
                    description = descriptions[0].get("value", "")

                # Extract CVSS metrics from top level
                metrics = cve_data.get("metrics", {})
                for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if version in metrics and metrics[version]:
                        metric = metrics[version][0] if isinstance(metrics[version], list) else metrics[version]
                        cvss_data = metric.get("cvssData", {})
                        severity = cvss_data.get("baseSeverity", metric.get("baseSeverity", "UNKNOWN"))
                        cvss_score = cvss_data.get("baseScore", metric.get("baseScore"))
                        break

                published = cve_data.get("published", "")
                references = cve_data.get("references", [])

            if not description:
                return None

            # Extract affected products and versions from CNA
            affected_products = []
            if cna:
                affected = cna.get("affected", [])
                for a in affected:
                    vendor = a.get("vendor", "")
                    product = a.get("product", "")
                    versions = a.get("versions", [])
                    version_info = []
                    for v in versions:
                        status = v.get("status", "")
                        version = v.get("version", "")
                        less_than = v.get("lessThan", "")
                        if status == "affected":
                            if less_than:
                                version_info.append(f"< {less_than}")
                            elif version and version != "unspecified":
                                version_info.append(version)
                    if vendor and product:
                        version_str = ", ".join(version_info) if version_info else "all versions"
                        affected_products.append(f"{vendor} {product} ({version_str})")

            # Extract references and patch links
            patch_links = []
            ref_urls = []
            for ref in references[:10]:
                url = ref.get("url", "") if isinstance(ref, dict) else str(ref)
                if url:
                    ref_urls.append(url)
                    tags = ref.get("tags", []) if isinstance(ref, dict) else []
                    if "Patch" in tags or "Vendor Advisory" in tags:
                        patch_links.append(url)

            # Add affected products to description if available
            full_description = description
            if affected_products:
                affected_str = "; ".join(affected_products[:5])  # Limit to first 5 products
                full_description = f"{description}\n\nAffected: {affected_str}"

            # Format to match NVD structure for _process_nvd_cve
            return {
                "cve": {
                    "id": cve_id.upper(),
                    "descriptions": [{"lang": "en", "value": full_description}],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": cvss_score,
                                "baseSeverity": severity.upper() if severity else "UNKNOWN"
                            }
                        }] if cvss_score else []
                    },
                    "published": published[:10] if published else "",
                    "references": [{"url": url, "tags": ["Patch"] if url in patch_links else []} for url in ref_urls[:5]],
                    "configurations": [],
                    "affected_products": affected_products  # Store separately too
                }
            }
        except Exception as e:
            logger.error(f"Error converting new CIRCL CVE {cve_id}: {e}")
            return None

    async def fetch_by_cpe(self, cpe_name: str, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Fetch CVEs by CPE (Common Platform Enumeration) name

        Examples:
        - cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*
        - cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*
        - cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*

        This is the most accurate way to find OS-specific vulnerabilities.
        """
        cves = []
        params = {
            "cpeName": cpe_name,
            "resultsPerPage": min(100, limit * 2),
            "startIndex": 0
        }

        headers = {}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key

        logger.info(f"Fetching CVEs for CPE: {cpe_name}")

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                while len(cves) < limit:
                    response = await client.get(
                        self.NVD_API_URL,
                        params=params,
                        headers=headers
                    )
                    response.raise_for_status()
                    data = response.json()

                    vulnerabilities = data.get("vulnerabilities", [])
                    if not vulnerabilities:
                        break

                    cves.extend(vulnerabilities)

                    total = data.get("totalResults", 0)
                    if params["startIndex"] + len(vulnerabilities) >= total:
                        break

                    params["startIndex"] += len(vulnerabilities)

                    # Rate limiting
                    if not self.nvd_api_key:
                        await asyncio.sleep(6)
                    else:
                        await asyncio.sleep(0.6)

        except httpx.HTTPError as e:
            logger.error(f"Error fetching CVEs for CPE '{cpe_name}': {e}")

        # Process the CVEs
        processed = []
        kev_cves = await self._fetch_cisa_kev()
        kev_ids = {cve["cveID"] for cve in kev_cves}

        for cve in cves[:limit]:
            p = self._process_nvd_cve(cve)
            if p:
                p["is_exploited"] = p["cve_id"] in kev_ids
                processed.append(p)

        logger.info(f"Found {len(processed)} CVEs for CPE: {cpe_name}")
        return processed

    async def _fetch_cisa_kev(self) -> List[Dict[str, Any]]:
        """Fetch CISA Known Exploited Vulnerabilities catalog"""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(self.CISA_KEV_URL)
                response.raise_for_status()
                data = response.json()
                return data.get("vulnerabilities", [])
        except httpx.HTTPError as e:
            logger.error(f"Error fetching CISA KEV: {e}")
            return []

    def _process_nvd_cve(self, vuln: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a single NVD CVE record into our format"""
        try:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")

            # Get description (prefer English)
            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Get CVSS metrics
            metrics = cve.get("metrics", {})
            severity = "UNKNOWN"
            cvss_score = None

            # Try CVSS 3.1 first, then 3.0, then 2.0
            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version in metrics and metrics[version]:
                    metric = metrics[version][0]
                    cvss_data = metric.get("cvssData", {})
                    severity = cvss_data.get("baseSeverity", metric.get("baseSeverity", "UNKNOWN"))
                    cvss_score = cvss_data.get("baseScore", metric.get("baseScore"))
                    break

            # Extract affected products/OS tags
            os_tags = self._extract_os_tags(cve)

            # Get references and patch links
            references = cve.get("references", [])
            patch_links = []
            for ref in references:
                tags = ref.get("tags", [])
                if "Patch" in tags or "Vendor Advisory" in tags:
                    patch_links.append(ref.get("url"))

            # Published date
            published = cve.get("published", "")

            return {
                "cve_id": cve_id,
                "title": cve_id,  # NVD doesn't have titles, use ID
                "description": description,
                "severity": severity.upper() if severity else "UNKNOWN",
                "cvss_score": cvss_score,
                "published_date": published[:10] if published else "",
                "os_tags": os_tags,
                "patch_links": patch_links[:3],  # Limit to first 3
                "references": [r.get("url") for r in references[:5]],
                "is_exploited": False  # Will be set later
            }
        except Exception as e:
            logger.error(f"Error processing CVE: {e}")
            return None

    def _extract_os_tags(self, cve: Dict[str, Any]) -> List[str]:
        """Extract OS/platform tags from CVE configurations"""
        tags = set()

        # Check description for OS mentions
        descriptions = cve.get("descriptions", [])
        for desc in descriptions:
            text = desc.get("value", "").lower()

            if "windows" in text:
                tags.add("windows")
                if "windows 10" in text:
                    tags.add("windows_10")
                if "windows 11" in text:
                    tags.add("windows_11")
                if "windows server" in text:
                    tags.add("windows_server")
            if "linux" in text:
                tags.add("linux")
                tags.add("unix")
            if "macos" in text or "mac os" in text or "darwin" in text:
                tags.add("macos")
                tags.add("darwin")
                tags.add("unix")
            if "android" in text:
                tags.add("android")
                tags.add("mobile")
            if "ios" in text or "iphone" in text or "ipad" in text:
                tags.add("ios")
                tags.add("apple_mobile")
            if "ubuntu" in text:
                tags.add("ubuntu")
                tags.add("linux")
            if "debian" in text:
                tags.add("debian")
                tags.add("linux")
            if "red hat" in text or "rhel" in text:
                tags.add("rhel")
                tags.add("linux")
            if "chrome" in text:
                tags.add("chrome")
            if "firefox" in text:
                tags.add("firefox")
            if "safari" in text:
                tags.add("safari")

        # Also check configurations if available
        configurations = cve.get("configurations", [])
        for config in configurations:
            nodes = config.get("nodes", [])
            for node in nodes:
                cpe_matches = node.get("cpeMatch", [])
                for cpe in cpe_matches:
                    criteria = cpe.get("criteria", "").lower()
                    if "microsoft:windows" in criteria:
                        tags.add("windows")
                    if "linux" in criteria:
                        tags.add("linux")
                    if "apple:mac" in criteria or "apple:macos" in criteria:
                        tags.add("macos")
                    if "google:android" in criteria:
                        tags.add("android")
                    if "apple:iphone_os" in criteria:
                        tags.add("ios")

        return list(tags)

    def _severity_score(self, severity: str) -> int:
        """Convert severity string to numeric score for sorting"""
        scores = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1,
            "UNKNOWN": 0
        }
        return scores.get(severity.upper(), 0)

    def _is_cache_valid(self) -> bool:
        """Check if cache file exists and is still valid"""
        if not self.cache_file.exists():
            return False

        try:
            mtime = datetime.fromtimestamp(self.cache_file.stat().st_mtime)
            return datetime.now() - mtime < self.cache_ttl
        except Exception:
            return False

    def _load_cache(self) -> List[Dict[str, Any]]:
        """Load CVE data from cache file"""
        try:
            with open(self.cache_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading cache: {e}")
            return []

    def _save_cache(self, cves: List[Dict[str, Any]]) -> None:
        """Save CVE data to cache file"""
        try:
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(cves, f, ensure_ascii=False, indent=2)
            logger.info(f"Saved {len(cves)} CVEs to cache")
        except Exception as e:
            logger.error(f"Error saving cache: {e}")

    def _convert_circl_to_standard(self, cve_id: str, cve_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Convert CIRCL CVE API format to our standard NVD-like format.

        CIRCL API returns data in CVE 5.x format which is different from NVD 2.0.
        """
        try:
            summary = ""
            cvss_score = None
            severity = "UNKNOWN"
            references = []
            published = ""

            # Handle CVE 5.x format (new format from CIRCL)
            if isinstance(cve_data, dict):
                # Check for CVE 5.x format
                if "containers" in cve_data:
                    cna = cve_data.get("containers", {}).get("cna", {})

                    # Get description
                    descriptions = cna.get("descriptions", [])
                    for desc in descriptions:
                        if desc.get("lang") == "en":
                            summary = desc.get("value", "")
                            break
                    if not summary and descriptions:
                        summary = descriptions[0].get("value", "")

                    # Get references
                    refs = cna.get("references", [])
                    for ref in refs[:10]:
                        if isinstance(ref, dict):
                            url = ref.get("url", "")
                            if url:
                                references.append(url)

                    # Get CVSS from metrics
                    metrics = cna.get("metrics", [])
                    for metric in metrics:
                        if "cvssV3_1" in metric:
                            cvss_data = metric["cvssV3_1"]
                            cvss_score = cvss_data.get("baseScore")
                            severity = cvss_data.get("baseSeverity", "UNKNOWN").upper()
                            break
                        elif "cvssV3_0" in metric:
                            cvss_data = metric["cvssV3_0"]
                            cvss_score = cvss_data.get("baseScore")
                            severity = cvss_data.get("baseSeverity", "UNKNOWN").upper()
                            break

                    # Get published date from metadata
                    metadata = cve_data.get("cveMetadata", {})
                    published = metadata.get("datePublished", "")

                # Handle old CIRCL format (fallback)
                elif "summary" in cve_data:
                    summary = cve_data.get("summary", "")
                    cvss_score = cve_data.get("cvss3") or cve_data.get("cvss")
                    if cvss_score:
                        cvss_score = float(cvss_score)
                    references = cve_data.get("references", [])
                    published = cve_data.get("Published", cve_data.get("published", ""))

            elif isinstance(cve_data, str):
                summary = cve_data

            if not summary:
                return None

            # Determine severity from CVSS score if not already set
            if severity == "UNKNOWN" and cvss_score:
                if cvss_score >= 9.0:
                    severity = "CRITICAL"
                elif cvss_score >= 7.0:
                    severity = "HIGH"
                elif cvss_score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

            # Infer severity from description if no CVSS
            if severity == "UNKNOWN":
                desc_lower = summary.lower()
                if "critical" in desc_lower:
                    severity = "CRITICAL"
                elif "high" in desc_lower:
                    severity = "HIGH"
                elif "medium" in desc_lower or "moderate" in desc_lower:
                    severity = "MEDIUM"
                elif "low" in desc_lower:
                    severity = "LOW"

            # Extract patch links from references
            patch_links = []
            ref_urls = []
            for ref in references[:10]:
                url = ref if isinstance(ref, str) else ref.get("url", "") if isinstance(ref, dict) else ""
                if url:
                    ref_urls.append(url)
                    if any(x in url.lower() for x in ["patch", "advisory", "security", "update"]):
                        patch_links.append(url)

            # Format to match NVD structure for _process_nvd_cve
            return {
                "cve": {
                    "id": cve_id.upper(),
                    "descriptions": [{"lang": "en", "value": summary}],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": cvss_score,
                                "baseSeverity": severity
                            }
                        }] if cvss_score else []
                    },
                    "published": published[:10] if published else "",
                    "references": [{"url": url, "tags": ["Patch"] if url in patch_links else []} for url in ref_urls[:5]],
                    "configurations": []
                }
            }
        except Exception as e:
            logger.error(f"Error converting CIRCL CVE {cve_id}: {e}")
            return None

    def _extract_os_tags_from_text(self, text: str) -> List[str]:
        """Extract OS/platform tags from CVE description text"""
        if not text:
            return []

        tags = set()
        text_lower = text.lower()

        if "windows" in text_lower:
            tags.add("windows")
            if "windows 10" in text_lower:
                tags.add("windows_10")
            if "windows 11" in text_lower:
                tags.add("windows_11")
            if "windows server" in text_lower:
                tags.add("windows_server")
        if "linux" in text_lower:
            tags.add("linux")
            tags.add("unix")
        if "macos" in text_lower or "mac os" in text_lower or "darwin" in text_lower:
            tags.add("macos")
            tags.add("darwin")
            tags.add("unix")
        if "android" in text_lower:
            tags.add("android")
            tags.add("mobile")
        if "ios" in text_lower or "iphone" in text_lower or "ipad" in text_lower:
            tags.add("ios")
            tags.add("apple_mobile")
        if "ubuntu" in text_lower:
            tags.add("ubuntu")
            tags.add("linux")
        if "debian" in text_lower:
            tags.add("debian")
            tags.add("linux")
        if "chrome" in text_lower or "chromium" in text_lower:
            tags.add("chrome")
        if "firefox" in text_lower:
            tags.add("firefox")
        if "safari" in text_lower or "webkit" in text_lower:
            tags.add("safari")

        return list(tags)

    async def _fetch_by_keyword_nvd(self, keyword: str, limit: int = 50, years: int = 5) -> List[Dict[str, Any]]:
        """
        Fallback: Fetch CVEs by keyword from NVD API.

        Note: NVD API may have issues with future dates (2026+).
        """
        cves = []

        # Calculate min year for post-filtering
        current_year = datetime.now().year
        min_year = current_year - years

        # NVD API - don't use date parameters (can cause 404), filter results after
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(100, limit * 3),  # Fetch more to filter by year
            "startIndex": 0
        }

        headers = {}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key

        logger.info(f"Fetching CVEs from NVD API for keyword: {keyword} (years: {years})")

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                while len(cves) < limit * 2:
                    response = await client.get(
                        self.NVD_API_URL,
                        params=params,
                        headers=headers
                    )
                    response.raise_for_status()
                    data = response.json()

                    vulnerabilities = data.get("vulnerabilities", [])
                    if not vulnerabilities:
                        break

                    cves.extend(vulnerabilities)

                    total = data.get("totalResults", 0)
                    if params["startIndex"] + len(vulnerabilities) >= total:
                        break

                    params["startIndex"] += len(vulnerabilities)

                    # Rate limiting
                    if not self.nvd_api_key:
                        await asyncio.sleep(6)
                    else:
                        await asyncio.sleep(0.6)

        except httpx.HTTPError as e:
            logger.error(f"NVD API error for keyword '{keyword}': {e}")

        # Process the CVEs with year filtering
        processed = []
        kev_cves = await self._fetch_cisa_kev()
        kev_ids = {cve["cveID"] for cve in kev_cves}

        for cve in cves:
            p = self._process_nvd_cve(cve)
            if p:
                # Filter by year from CVE ID (CVE-YYYY-XXXXX)
                try:
                    cve_year = int(p["cve_id"].split('-')[1])
                    if cve_year < min_year:
                        continue  # Skip old CVEs
                except (IndexError, ValueError):
                    pass  # If can't parse year, include it

                p["is_exploited"] = p["cve_id"] in kev_ids
                processed.append(p)

        # Sort by date (newest first) then by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        processed.sort(
            key=lambda x: (
                x.get("published_date", "0000-00-00"),
                severity_order.get(x.get("severity", "UNKNOWN"), 4)
            ),
            reverse=True
        )

        # Limit results after sorting
        processed = processed[:limit]

        logger.info(f"Found {len(processed)} CVEs from NVD for keyword: {keyword}")
        return processed
