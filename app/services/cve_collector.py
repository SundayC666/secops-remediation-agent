"""
CVE Data Collector - Simplified Version
Primary source: NVD API with virtualMatchString (precise CPE-based search)
Secondary source: CISA KEV catalog (for marking actively exploited CVEs)
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


# CPE mapping for common products
# Format: keyword -> (vendor, product, cpe_type) or keyword -> list of (vendor, product, cpe_type)
# cpe_type: 'o' = operating system, 'a' = application, 'h' = hardware
# Multi-version support for comprehensive CVE coverage
CPE_MAPPING = {
    # =========================================================================
    # Microsoft Windows - Multiple version-specific CPEs
    # =========================================================================
    "windows": [
        ("microsoft", "windows_10_22h2", "o"),
        ("microsoft", "windows_11_24h2", "o"),
    ],
    "windows 10": [
        ("microsoft", "windows_10_22h2", "o"),
        ("microsoft", "windows_10_21h2", "o"),
        ("microsoft", "windows_10_1809", "o"),
    ],
    "windows 11": [
        ("microsoft", "windows_11_24h2", "o"),
        ("microsoft", "windows_11_23h2", "o"),
        ("microsoft", "windows_11_22h2", "o"),
        ("microsoft", "windows_11_21h2", "o"),
    ],
    "windows server": [
        ("microsoft", "windows_server_2022", "o"),
        ("microsoft", "windows_server_2019", "o"),
        ("microsoft", "windows_server_2016", "o"),
    ],
    "windows server 2016": ("microsoft", "windows_server_2016", "o"),
    "windows server 2019": ("microsoft", "windows_server_2019", "o"),
    "windows server 2022": ("microsoft", "windows_server_2022", "o"),

    # =========================================================================
    # Apple - macOS, iOS, iPadOS with version-specific CPEs
    # =========================================================================
    "macos": [
        ("apple", "macos", "o"),  # Generic - catches all versions
        ("apple", "mac_os_x", "o"),  # Legacy naming
    ],
    "mac os": [
        ("apple", "macos", "o"),
        ("apple", "mac_os_x", "o"),
    ],
    "macos sequoia": ("apple", "macos", "o"),  # macOS 15
    "macos sonoma": ("apple", "macos", "o"),   # macOS 14
    "macos ventura": ("apple", "macos", "o"),  # macOS 13
    "macos monterey": ("apple", "macos", "o"), # macOS 12

    "ios": [
        ("apple", "iphone_os", "o"),  # NVD uses iphone_os for iOS
    ],
    "ipados": [
        ("apple", "ipados", "o"),
        ("apple", "iphone_os", "o"),  # Some CVEs list both
    ],
    "watchos": ("apple", "watchos", "o"),
    "tvos": ("apple", "tvos", "o"),
    "visionos": ("apple", "visionos", "o"),
    "safari": ("apple", "safari", "a"),
    "xcode": ("apple", "xcode", "a"),

    # =========================================================================
    # Linux Distributions - Multiple versions
    # =========================================================================
    "linux": [
        ("linux", "linux_kernel", "o"),
    ],
    "ubuntu": [
        ("canonical", "ubuntu_linux", "o"),
    ],
    "ubuntu 24.04": ("canonical", "ubuntu_linux", "o"),
    "ubuntu 22.04": ("canonical", "ubuntu_linux", "o"),
    "ubuntu 20.04": ("canonical", "ubuntu_linux", "o"),

    "debian": [
        ("debian", "debian_linux", "o"),
    ],
    "debian 12": ("debian", "debian_linux", "o"),
    "debian 11": ("debian", "debian_linux", "o"),

    "redhat": [
        ("redhat", "enterprise_linux", "o"),
    ],
    "rhel": [
        ("redhat", "enterprise_linux", "o"),
    ],
    "rhel 9": ("redhat", "enterprise_linux", "o"),
    "rhel 8": ("redhat", "enterprise_linux", "o"),

    "centos": [
        ("centos", "centos", "o"),
        ("centos", "centos_stream", "o"),
    ],
    "fedora": [
        ("fedoraproject", "fedora", "o"),
    ],
    "rocky linux": ("rocky", "rocky", "o"),
    "alma linux": ("almalinux", "almalinux", "o"),
    "suse": ("suse", "linux_enterprise_server", "o"),
    "opensuse": ("opensuse", "leap", "o"),
    "arch linux": ("archlinux", "arch_linux", "o"),

    # =========================================================================
    # Android - Multiple versions
    # =========================================================================
    "android": [
        ("google", "android", "o"),
    ],
    "android 14": ("google", "android", "o"),
    "android 13": ("google", "android", "o"),
    "android 12": ("google", "android", "o"),

    # =========================================================================
    # Browsers - Multiple browsers and versions
    # =========================================================================
    "chrome": [
        ("google", "chrome", "a"),
    ],
    "google chrome": ("google", "chrome", "a"),
    "chromium": ("chromium", "chromium", "a"),

    "firefox": [
        ("mozilla", "firefox", "a"),
        ("mozilla", "firefox_esr", "a"),  # Extended Support Release
    ],
    "firefox esr": ("mozilla", "firefox_esr", "a"),

    "edge": [
        ("microsoft", "edge", "a"),
        ("microsoft", "edge_chromium", "a"),
    ],
    "microsoft edge": ("microsoft", "edge", "a"),

    "safari": ("apple", "safari", "a"),
    "opera": ("opera", "opera_browser", "a"),
    "brave": ("brave", "brave", "a"),

    # =========================================================================
    # Microsoft Products
    # =========================================================================
    "office": [
        ("microsoft", "365_apps", "a"),
        ("microsoft", "office", "a"),
    ],
    "microsoft 365": ("microsoft", "365_apps", "a"),
    "office 365": ("microsoft", "365_apps", "a"),

    "exchange": [
        ("microsoft", "exchange_server", "a"),
    ],
    "exchange server": ("microsoft", "exchange_server", "a"),
    "exchange 2019": ("microsoft", "exchange_server", "a"),
    "exchange 2016": ("microsoft", "exchange_server", "a"),

    "outlook": ("microsoft", "outlook", "a"),
    "teams": ("microsoft", "teams", "a"),
    "sharepoint": ("microsoft", "sharepoint_server", "a"),
    "azure": ("microsoft", "azure", "a"),
    "sql server": ("microsoft", "sql_server", "a"),
    ".net": ("microsoft", ".net", "a"),
    "visual studio": ("microsoft", "visual_studio", "a"),
    "powershell": ("microsoft", "powershell", "a"),

    # =========================================================================
    # Adobe Products
    # =========================================================================
    "adobe reader": ("adobe", "acrobat_reader_dc", "a"),
    "acrobat reader": ("adobe", "acrobat_reader_dc", "a"),
    "acrobat": [
        ("adobe", "acrobat_dc", "a"),
        ("adobe", "acrobat", "a"),
    ],
    "photoshop": ("adobe", "photoshop", "a"),
    "illustrator": ("adobe", "illustrator", "a"),
    "premiere": ("adobe", "premiere_pro", "a"),
    "after effects": ("adobe", "after_effects", "a"),
    "indesign": ("adobe", "indesign", "a"),
    "creative cloud": ("adobe", "creative_cloud_desktop_application", "a"),
    "flash player": ("adobe", "flash_player", "a"),
    "coldfusion": ("adobe", "coldfusion", "a"),

    # =========================================================================
    # Oracle/Java Products
    # =========================================================================
    "java": [
        ("oracle", "jdk", "a"),
        ("oracle", "jre", "a"),
        ("oracle", "graalvm", "a"),
    ],
    "jdk": ("oracle", "jdk", "a"),
    "jre": ("oracle", "jre", "a"),
    "openjdk": ("openjdk", "jdk", "a"),
    "oracle database": ("oracle", "database", "a"),
    "mysql": [
        ("oracle", "mysql", "a"),
        ("mysql", "mysql", "a"),
    ],
    "weblogic": ("oracle", "weblogic_server", "a"),

    # =========================================================================
    # Web Servers & Proxies
    # =========================================================================
    "apache": [
        ("apache", "http_server", "a"),
    ],
    "apache http server": ("apache", "http_server", "a"),
    "httpd": ("apache", "http_server", "a"),

    "nginx": ("nginx", "nginx", "a"),
    "tomcat": ("apache", "tomcat", "a"),
    "iis": ("microsoft", "internet_information_services", "a"),
    "caddy": ("caddyserver", "caddy", "a"),
    "lighttpd": ("lighttpd", "lighttpd", "a"),
    "haproxy": ("haproxy", "haproxy", "a"),
    "traefik": ("traefik", "traefik", "a"),

    # =========================================================================
    # Databases
    # =========================================================================
    "postgresql": ("postgresql", "postgresql", "a"),
    "postgres": ("postgresql", "postgresql", "a"),
    "mariadb": ("mariadb", "mariadb", "a"),
    "mongodb": ("mongodb", "mongodb", "a"),
    "redis": ("redis", "redis", "a"),
    "elasticsearch": ("elastic", "elasticsearch", "a"),
    "sqlite": ("sqlite", "sqlite", "a"),
    "cassandra": ("apache", "cassandra", "a"),
    "couchdb": ("apache", "couchdb", "a"),

    # =========================================================================
    # Containers & Orchestration
    # =========================================================================
    "docker": [
        ("docker", "docker", "a"),
        ("mobyproject", "moby", "a"),
    ],
    "kubernetes": ("kubernetes", "kubernetes", "a"),
    "k8s": ("kubernetes", "kubernetes", "a"),
    "openshift": ("redhat", "openshift", "a"),
    "containerd": ("linuxfoundation", "containerd", "a"),
    "podman": ("podman_project", "podman", "a"),
    "helm": ("helm", "helm", "a"),
    "rancher": ("rancher", "rancher", "a"),

    # =========================================================================
    # CI/CD & DevOps Tools
    # =========================================================================
    "jenkins": ("jenkins", "jenkins", "a"),
    "gitlab": ("gitlab", "gitlab", "a"),
    "github": ("github", "enterprise_server", "a"),
    "github enterprise": ("github", "enterprise_server", "a"),
    "bitbucket": ("atlassian", "bitbucket", "a"),
    "bamboo": ("atlassian", "bamboo", "a"),
    "jira": ("atlassian", "jira", "a"),
    "confluence": ("atlassian", "confluence", "a"),
    "ansible": ("redhat", "ansible", "a"),
    "terraform": ("hashicorp", "terraform", "a"),
    "vault": ("hashicorp", "vault", "a"),
    "consul": ("hashicorp", "consul", "a"),
    "argocd": ("argoproj", "argo_cd", "a"),

    # =========================================================================
    # CMS & Web Applications
    # =========================================================================
    "wordpress": ("wordpress", "wordpress", "a"),
    "drupal": ("drupal", "drupal", "a"),
    "joomla": ("joomla", "joomla\\!", "a"),
    "magento": ("adobe", "magento", "a"),
    "shopify": ("shopify", "shopify", "a"),
    "woocommerce": ("woocommerce", "woocommerce", "a"),

    # =========================================================================
    # Programming Languages & Runtimes
    # =========================================================================
    "python": ("python", "python", "a"),
    "node.js": ("nodejs", "node.js", "a"),
    "nodejs": ("nodejs", "node.js", "a"),
    "node": ("nodejs", "node.js", "a"),
    "php": ("php", "php", "a"),
    "ruby": ("ruby-lang", "ruby", "a"),
    "go": ("golang", "go", "a"),
    "golang": ("golang", "go", "a"),
    "rust": ("rust-lang", "rust", "a"),
    "perl": ("perl", "perl", "a"),

    # =========================================================================
    # Networking & Security
    # =========================================================================
    "cisco ios": ("cisco", "ios", "o"),
    "cisco": [
        ("cisco", "ios", "o"),
        ("cisco", "ios_xe", "o"),
        ("cisco", "nx-os", "o"),
    ],
    "cisco ios xe": ("cisco", "ios_xe", "o"),
    "cisco nx-os": ("cisco", "nx-os", "o"),

    "fortinet": [
        ("fortinet", "fortios", "o"),
        ("fortinet", "fortigate", "h"),
    ],
    "fortigate": ("fortinet", "fortios", "o"),
    "fortios": ("fortinet", "fortios", "o"),

    "palo alto": [
        ("paloaltonetworks", "pan-os", "o"),
    ],
    "pan-os": ("paloaltonetworks", "pan-os", "o"),

    "juniper": ("juniper", "junos", "o"),
    "junos": ("juniper", "junos", "o"),

    "checkpoint": ("checkpoint", "gaia_os", "o"),
    "sophos": ("sophos", "sophos_firewall", "a"),
    "f5": ("f5", "big-ip_access_policy_manager", "a"),
    "big-ip": ("f5", "big-ip_access_policy_manager", "a"),

    # =========================================================================
    # VPN & Remote Access
    # =========================================================================
    "openssl": ("openssl", "openssl", "a"),
    "openvpn": ("openvpn", "openvpn", "a"),
    "wireguard": ("wireguard", "wireguard", "a"),
    "pulse secure": ("pulsesecure", "pulse_connect_secure", "a"),
    "citrix": ("citrix", "netscaler_gateway", "a"),
    "netscaler": ("citrix", "netscaler_gateway", "a"),

    # =========================================================================
    # Virtualization
    # =========================================================================
    "vmware": [
        ("vmware", "vcenter_server", "a"),
        ("vmware", "esxi", "o"),
    ],
    "vcenter": ("vmware", "vcenter_server", "a"),
    "esxi": ("vmware", "esxi", "o"),
    "vsphere": ("vmware", "vsphere", "a"),
    "virtualbox": ("oracle", "vm_virtualbox", "a"),
    "hyper-v": ("microsoft", "hyper-v", "a"),
    "proxmox": ("proxmox", "virtual_environment", "a"),
    "qemu": ("qemu", "qemu", "a"),
    "kvm": ("linux", "kernel", "o"),

    # =========================================================================
    # Messaging & Collaboration
    # =========================================================================
    "slack": ("slack", "slack", "a"),
    "zoom": ("zoom", "zoom", "a"),
    "webex": ("cisco", "webex_meetings", "a"),
    "discord": ("discord", "discord", "a"),

    # =========================================================================
    # Cloud Platforms
    # =========================================================================
    "aws": ("amazon", "aws", "a"),
    "gcp": ("google", "cloud_platform", "a"),
    "google cloud": ("google", "cloud_platform", "a"),
}


class CVEDataCollector:
    """
    Simplified CVE Data Collector
    - Primary: NVD API with virtualMatchString (precise CPE-based search)
    - Secondary: CISA KEV for marking actively exploited vulnerabilities
    """

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self):
        self.nvd_api_key = getattr(settings, 'NVD_API_KEY', None)
        self.max_results = getattr(settings, 'CVE_MAX_RESULTS', 100)
        self._kev_cache: Optional[List[Dict]] = None
        self._kev_cache_time: Optional[datetime] = None

    async def fetch_by_keyword(self, keyword: str, limit: int = 50, years: int = 3) -> List[Dict[str, Any]]:
        """
        Fetch CVEs by keyword using NVD virtualMatchString (CPE-based search).

        Args:
            keyword: Search keyword (e.g., 'windows 11', 'macos', 'chrome')
            limit: Maximum number of results
            years: Only fetch CVEs from the last N years (default: 3)

        Returns:
            List of CVE records sorted by date (newest first) and severity
        """
        keyword_lower = keyword.lower().strip()

        # Build CPE strings from keyword (may return multiple for Windows)
        cpe_strings = self._build_cpe_strings(keyword_lower)
        if not cpe_strings:
            logger.warning(f"No CPE mapping found for: {keyword}")
            return []

        logger.info(f"Searching NVD for: {keyword} -> CPEs: {cpe_strings}")

        # Calculate date range for filtering (will be applied post-fetch)
        current_year = datetime.now().year
        min_year = current_year - years

        # Fetch from NVD for each CPE string
        all_cves = []
        seen_cve_ids = set()

        for cpe_string in cpe_strings:
            cves = await self._fetch_nvd_cpe(cpe_string, limit, min_year)
            for cve in cves:
                cve_id = cve.get("cve", {}).get("id", "")
                if cve_id and cve_id not in seen_cve_ids:
                    seen_cve_ids.add(cve_id)
                    all_cves.append(cve)

        # Fetch KEV data for marking exploited CVEs
        kev_ids = await self._get_kev_ids()

        # Process and enrich results
        processed = []
        for cve in all_cves:
            p = self._process_nvd_cve(cve)
            if p:
                p["is_exploited"] = p["cve_id"] in kev_ids
                processed.append(p)

        # Sort by date (newest first), then by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        processed.sort(
            key=lambda x: (
                x.get("published_date", ""),
                -severity_order.get(x.get("severity", "UNKNOWN"), 4)
            ),
            reverse=True
        )

        logger.info(f"Found {len(processed)} unique CVEs for {keyword}")
        return processed[:limit]

    def _build_cpe_strings(self, keyword: str) -> List[str]:
        """
        Build CPE 2.3 strings from keyword.
        Returns a list of CPE strings (multiple for products like Windows with version-specific CPEs).
        """
        cpe_strings = []

        # Direct match
        if keyword in CPE_MAPPING:
            mapping = CPE_MAPPING[keyword]
            # Check if it's a list of tuples or a single tuple
            if isinstance(mapping, list):
                for vendor, product, cpe_type in mapping:
                    cpe_strings.append(f"cpe:2.3:{cpe_type}:{vendor}:{product}:*:*:*:*:*:*:*:*")
            else:
                vendor, product, cpe_type = mapping
                cpe_strings.append(f"cpe:2.3:{cpe_type}:{vendor}:{product}:*:*:*:*:*:*:*:*")
            return cpe_strings

        # Try with underscores
        keyword_underscore = keyword.replace(" ", "_")
        if keyword_underscore in CPE_MAPPING:
            mapping = CPE_MAPPING[keyword_underscore]
            if isinstance(mapping, list):
                for vendor, product, cpe_type in mapping:
                    cpe_strings.append(f"cpe:2.3:{cpe_type}:{vendor}:{product}:*:*:*:*:*:*:*:*")
            else:
                vendor, product, cpe_type = mapping
                cpe_strings.append(f"cpe:2.3:{cpe_type}:{vendor}:{product}:*:*:*:*:*:*:*:*")
            return cpe_strings

        # Try partial match (e.g., "windows 11" contains "windows")
        for key, mapping in CPE_MAPPING.items():
            if key in keyword or keyword in key:
                if isinstance(mapping, list):
                    for vendor, product, cpe_type in mapping:
                        cpe_strings.append(f"cpe:2.3:{cpe_type}:{vendor}:{product}:*:*:*:*:*:*:*:*")
                else:
                    vendor, product, cpe_type = mapping
                    cpe_strings.append(f"cpe:2.3:{cpe_type}:{vendor}:{product}:*:*:*:*:*:*:*:*")
                return cpe_strings

        # Fallback: try to construct CPE from keyword parts
        parts = keyword.split()
        if len(parts) >= 1:
            # Assume first part is vendor/product
            product = parts[0].replace(" ", "_")
            cpe_strings.append(f"cpe:2.3:*:*:{product}:*:*:*:*:*:*:*:*")

        return cpe_strings

    async def _fetch_nvd_cpe(self, cpe_string: str, limit: int, min_year: int) -> List[Dict]:
        """
        Fetch CVEs from NVD using virtualMatchString (CPE-based search).
        This is the most precise way to search NVD.

        Note: NVD API does not support date filters with virtualMatchString,
        so we fetch all results and filter by year post-fetch.

        Args:
            cpe_string: CPE 2.3 format string
            limit: Maximum results to fetch
            min_year: Minimum publication year to include
        """
        # virtualMatchString doesn't work with date filters, use direct fetch with year filtering
        return await self._fetch_nvd_cpe_no_date_filter(cpe_string, limit, min_year)

    async def _fetch_nvd_cpe_no_date_filter(self, cpe_string: str, limit: int, min_year: int) -> List[Dict]:
        """
        Fetch CVEs using CPE search, scanning from the END of results (newest CVE IDs first).
        NVD returns CVEs sorted by CVE ID, so newer CVEs (with higher IDs) are at the end.
        """
        cves = []
        params = {
            "virtualMatchString": cpe_string,
            "resultsPerPage": 100,
            "startIndex": 0,
            "noRejected": ""  # Exclude rejected CVEs
        }

        headers = {"User-Agent": "SecOps-CVE-Collector/1.0"}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # First, get total count
                response = await client.get(self.NVD_API_URL, params=params, headers=headers)
                if response.status_code != 200:
                    logger.error(f"NVD API error: {response.status_code}")
                    return []

                data = response.json()
                total_results = data.get("totalResults", 0)

                if total_results == 0:
                    return []

                # Strategy: Start from the END (where newest CVE IDs are)
                # Scan backwards in chunks until we have enough recent CVEs
                pages_to_scan = min(6, (total_results // 100) + 1)  # Scan up to 6 pages from end
                start_indices = []

                for i in range(pages_to_scan):
                    idx = max(0, total_results - (i + 1) * 100)
                    if idx not in start_indices:
                        start_indices.append(idx)

                logger.info(f"NVD: {total_results} total CVEs, scanning from indices: {start_indices}")

                rate_limit_delay = 0.1 if self.nvd_api_key else 6.0

                for start_idx in start_indices:
                    if len(cves) >= limit:
                        break

                    params["startIndex"] = start_idx
                    response = await client.get(self.NVD_API_URL, params=params, headers=headers)

                    if response.status_code != 200:
                        logger.warning(f"NVD API error at index {start_idx}: {response.status_code}")
                        continue

                    data = response.json()
                    vulnerabilities = data.get("vulnerabilities", [])

                    # Filter by year
                    for vuln in vulnerabilities:
                        published = vuln.get("cve", {}).get("published", "")
                        if published:
                            try:
                                pub_year = int(published[:4])
                                if pub_year >= min_year:
                                    cves.append(vuln)
                            except (ValueError, IndexError):
                                pass

                    logger.info(f"NVD: scanned index {start_idx}, found {len(cves)} CVEs from {min_year}+")
                    await asyncio.sleep(rate_limit_delay)

        except Exception as e:
            logger.error(f"Error fetching from NVD: {e}")

        return cves

    async def _get_kev_ids(self) -> set:
        """
        Get set of CVE IDs from CISA KEV (Known Exploited Vulnerabilities).
        Results are cached for 1 hour.
        """
        # Check cache
        if self._kev_cache and self._kev_cache_time:
            if datetime.now() - self._kev_cache_time < timedelta(hours=1):
                return {cve["cveID"] for cve in self._kev_cache}

        # Fetch fresh data
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(self.CISA_KEV_URL)
                if response.status_code == 200:
                    data = response.json()
                    self._kev_cache = data.get("vulnerabilities", [])
                    self._kev_cache_time = datetime.now()
                    logger.info(f"Loaded {len(self._kev_cache)} KEV entries")
                    return {cve["cveID"] for cve in self._kev_cache}
        except Exception as e:
            logger.error(f"Failed to fetch CISA KEV: {e}")

        return set()

    def _process_nvd_cve(self, vuln_data: Dict) -> Optional[Dict]:
        """
        Process NVD CVE data into standardized format.
        """
        try:
            cve = vuln_data.get("cve", {})
            cve_id = cve.get("id", "")

            if not cve_id:
                return None

            # Get description
            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            if not description and descriptions:
                description = descriptions[0].get("value", "")

            # Get CVSS metrics
            metrics = cve.get("metrics", {})
            cvss_score = None
            severity = "UNKNOWN"
            cvss_vector = ""

            # Try CVSS 3.1 first, then 3.0, then 2.0
            for cvss_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                cvss_list = metrics.get(cvss_key, [])
                if cvss_list:
                    cvss_data = cvss_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    severity = cvss_data.get("baseSeverity", "UNKNOWN")
                    cvss_vector = cvss_data.get("vectorString", "")
                    break

            # Get dates
            published = cve.get("published", "")
            last_modified = cve.get("lastModified", "")

            # Get affected products from configurations
            affected_products = self._extract_affected_products(cve)

            # Get references
            references = cve.get("references", [])
            ref_urls = [ref.get("url", "") for ref in references[:10] if ref.get("url")]

            # Extract patch links
            patch_links = []
            for ref in references:
                url = ref.get("url", "")
                tags = ref.get("tags", [])
                if "Patch" in tags or "Vendor Advisory" in tags:
                    patch_links.append(url)

            return {
                "cve_id": cve_id,
                "title": f"{cve_id}: {description[:100]}..." if len(description) > 100 else f"{cve_id}: {description}",
                "description": description,
                "severity": severity.upper() if severity else "UNKNOWN",
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "published_date": published[:10] if published else "",
                "last_modified": last_modified[:10] if last_modified else "",
                "affected_versions": affected_products,
                "references": ref_urls,
                "patch_links": patch_links,
                "is_exploited": False,  # Will be set by caller
                "tags": self._extract_tags(description, affected_products),
            }

        except Exception as e:
            logger.error(f"Error processing CVE: {e}")
            return None

    def _extract_affected_products(self, cve: Dict) -> List[str]:
        """
        Extract affected products from CVE configurations.
        """
        affected = []
        configurations = cve.get("configurations", [])

        for config in configurations:
            nodes = config.get("nodes", [])
            for node in nodes:
                cpe_matches = node.get("cpeMatch", [])
                for cpe in cpe_matches:
                    if cpe.get("vulnerable", False):
                        criteria = cpe.get("criteria", "")
                        # Parse CPE: cpe:2.3:o:microsoft:windows_11:22h2:*:*:*:*:*:*:*
                        if criteria.startswith("cpe:2.3:"):
                            parts = criteria.split(":")
                            if len(parts) >= 6:
                                vendor = parts[3].replace("_", " ").title()
                                product = parts[4].replace("_", " ").title()
                                version = parts[5] if len(parts) > 5 and parts[5] != "*" else ""

                                # Build product string
                                if vendor.lower() != product.lower():
                                    product_str = f"{vendor} {product}"
                                else:
                                    product_str = product

                                # Add version info
                                version_end = cpe.get("versionEndExcluding") or cpe.get("versionEndIncluding")
                                version_start = cpe.get("versionStartIncluding")

                                if version_end:
                                    if version_start:
                                        product_str += f" {version_start} - {version_end}"
                                    else:
                                        product_str += f" before {version_end}"
                                elif version and version != "*":
                                    product_str += f" {version}"

                                if product_str not in affected:
                                    affected.append(product_str)

        return affected[:20]  # Limit to 20 entries

    def _extract_tags(self, description: str, affected_products: List[str]) -> List[str]:
        """
        Extract relevant tags from CVE description and affected products.
        """
        tags = set()
        text = (description + " " + " ".join(affected_products)).lower()

        # OS tags
        if "windows" in text:
            tags.add("windows")
        if "macos" in text or "mac os" in text:
            tags.add("macos")
        if "linux" in text:
            tags.add("linux")
        if "android" in text:
            tags.add("android")
        if "ios" in text or "iphone" in text or "ipad" in text:
            tags.add("ios")

        # Vulnerability type tags
        if "remote code execution" in text or "rce" in text:
            tags.add("rce")
        if "privilege escalation" in text or "elevation of privilege" in text:
            tags.add("privilege_escalation")
        if "denial of service" in text or "dos" in text:
            tags.add("dos")
        if "sql injection" in text:
            tags.add("sql_injection")
        if "cross-site scripting" in text or "xss" in text:
            tags.add("xss")
        if "buffer overflow" in text:
            tags.add("buffer_overflow")
        if "authentication" in text or "bypass" in text:
            tags.add("auth_bypass")

        return list(tags)

    # Keep backward compatibility - these methods are used by other parts of the system
    async def fetch_all(self, force_refresh: bool = False) -> List[Dict[str, Any]]:
        """
        Fetch recent CVEs for RAG initialization.
        This is a simplified version that fetches high-severity CVEs.
        """
        logger.info("Fetching recent high-severity CVEs for initialization...")

        # Fetch recent critical/high CVEs
        params = {
            "cvssV3Severity": "CRITICAL",
            "resultsPerPage": 100,
            "startIndex": 0
        }

        headers = {"User-Agent": "SecOps-CVE-Collector/1.0"}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key

        cves = []
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(self.NVD_API_URL, params=params, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities = data.get("vulnerabilities", [])

                    kev_ids = await self._get_kev_ids()

                    for vuln in vulnerabilities:
                        p = self._process_nvd_cve(vuln)
                        if p:
                            p["is_exploited"] = p["cve_id"] in kev_ids
                            cves.append(p)

                    logger.info(f"Fetched {len(cves)} CVEs for initialization")
        except Exception as e:
            logger.error(f"Failed to fetch CVEs for initialization: {e}")

        return cves

    async def fetch_cve_by_id(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch a specific CVE by ID.
        """
        params = {"cveId": cve_id}
        headers = {"User-Agent": "SecOps-CVE-Collector/1.0"}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(self.NVD_API_URL, params=params, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    if vulnerabilities:
                        kev_ids = await self._get_kev_ids()
                        p = self._process_nvd_cve(vulnerabilities[0])
                        if p:
                            p["is_exploited"] = p["cve_id"] in kev_ids
                            return p
        except Exception as e:
            logger.error(f"Failed to fetch CVE {cve_id}: {e}")

        return None
