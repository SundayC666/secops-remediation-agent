"""
CVE Data Collection Module
Fetches vulnerability data from NIST NVD API
"""

import requests
import json
import time
import os
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CVEDataCollector:
    """Collects CVE data from NIST National Vulnerability Database"""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize CVE data collector
        
        Args:
            api_key: NVD API key (optional, but increases rate limit)
        """
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = api_key
        self.headers = {}
        if api_key:
            self.headers['apiKey'] = api_key
        
        # Rate limiting: 5 requests per 30 seconds without key, 50 with key
        self.rate_limit_delay = 6 if not api_key else 0.6
        
    def fetch_recent_cves(self, days: int = 90, max_results: int = 200) -> List[Dict]:
        """
        Fetch recent CVEs from the last N days
        
        Args:
            days: Number of days to look back (default: 90 for quarterly coverage)
            max_results: Maximum number of CVEs to fetch (default: 200)
            
        Returns:
            List of CVE dictionaries
        """
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # NIST NVD API requires strict ISO 8601 date format
        params = {
            'pubStartDate': start_date.strftime('%Y-%m-%dT00:00:00.000'),
            'pubEndDate': end_date.strftime('%Y-%m-%dT23:59:59.999'),
            'resultsPerPage': min(max_results, 2000)
        }
        
        logger.info(f"Fetching CVEs from {start_date.date()} to {end_date.date()}")
        
        try:
            response = requests.get(
                self.base_url,
                params=params,
                headers=self.headers,
                timeout=30
            )
            response.raise_for_status()
            
            # Respect rate limits
            time.sleep(self.rate_limit_delay)
            
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            
            logger.info(f"Successfully fetched {len(vulnerabilities)} CVEs")
            return self._parse_cves(vulnerabilities)
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching CVEs: {e}")
            return []
    
    def fetch_specific_cve(self, cve_id: str) -> Optional[Dict]:
        """
        Fetch a specific CVE by ID
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234)
            
        Returns:
            CVE dictionary or None if not found
        """
        params = {'cveId': cve_id}
        
        try:
            response = requests.get(
                self.base_url,
                params=params,
                headers=self.headers,
                timeout=30
            )
            response.raise_for_status()
            time.sleep(self.rate_limit_delay)
            
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            
            if vulnerabilities:
                parsed = self._parse_cves(vulnerabilities)
                return parsed[0] if parsed else None
            return None
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching CVE {cve_id}: {e}")
            return None
    
    def _parse_cves(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Parse raw CVE data into structured format"""
        parsed_cves = []
        
        for vuln in vulnerabilities:
            cve = vuln.get('cve', {})
            cve_id = cve.get('id', 'Unknown')
            
            # Extract description
            descriptions = cve.get('descriptions', [])
            description = next(
                (d['value'] for d in descriptions if d.get('lang') == 'en'),
                'No description available'
            )
            
            # Extract CVSS scores
            metrics = cve.get('metrics', {})
            # Try V3.1 first, then fallback to V3.0 or V2
            cvss_data = {}
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
            elif 'cvssMetricV30' in metrics:
                cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
            elif 'cvssMetricV2' in metrics:
                cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
            
            cvss_score = cvss_data.get('baseScore', 0.0)
            cvss_severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            
            # Extract affected products (CPE)
            configurations = cve.get('configurations', [])
            affected_products = []
            for config in configurations:
                for node in config.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        if cpe_match.get('vulnerable'):
                            criteria = cpe_match.get('criteria', '')
                            affected_products.append(criteria)
            
            # Extract references
            references = cve.get('references', [])
            reference_urls = [ref.get('url') for ref in references[:3]]  # First 3 refs
            
            # Published date
            published = cve.get('published', '')
            
            parsed_cve = {
                'cve_id': cve_id,
                'description': description,
                'cvss_score': cvss_score,
                'severity': cvss_severity,
                'affected_products': affected_products[:10],  # Limit to 10 products
                'references': reference_urls,
                'published_date': published,
                'full_text': self._create_full_text(
                    cve_id, description, cvss_score, 
                    cvss_severity, affected_products, published
                )
            }
            
            parsed_cves.append(parsed_cve)
        
        return parsed_cves
    
    def _create_full_text(self, cve_id: str, description: str, 
                         cvss_score: float, severity: str,
                         affected_products: List[str], published: str) -> str:
        """Create a full text representation for embedding"""
        text = f"""CVE ID: {cve_id}
Severity: {severity} (CVSS Score: {cvss_score})
Published: {published}

Description:
{description}

Affected Products:
{chr(10).join('- ' + prod for prod in affected_products[:5])}

This vulnerability has a {severity.lower()} severity rating with a CVSS score of {cvss_score}.
Organizations using the affected products should prioritize remediation based on this severity level.
"""
        return text
    
    def save_to_file(self, cves: List[Dict], filename: str = 'cve_data.json'):
        """Save CVE data to JSON file"""
        os.makedirs('data', exist_ok=True)
        filepath = os.path.join('data', filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(cves, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Saved {len(cves)} CVEs to {filepath}")
    
    def load_from_file(self, filename: str = 'cve_data.json') -> List[Dict]:
        """Load CVE data from JSON file"""
        filepath = os.path.join('data', filename)
        
        if not os.path.exists(filepath):
            logger.warning(f"File {filepath} not found")
            return []
        
        with open(filepath, 'r', encoding='utf-8') as f:
            cves = json.load(f)
        
        logger.info(f"Loaded {len(cves)} CVEs from {filepath}")
        return cves


if __name__ == "__main__":
    # Test the collector
    collector = CVEDataCollector()
    
    # Fetch recent CVEs (90 days, 200 results)
    print("Fetching recent CVEs...")
    cves = collector.fetch_recent_cves(days=90, max_results=200)
    
    if cves:
        print(f"\nFetched {len(cves)} CVEs")
        print(f"\nExample CVE: {cves[0]['cve_id']}")
        print(f"Severity: {cves[0]['severity']}")
        print(f"Description: {cves[0]['description'][:200]}...")
        
        # Save to file
        collector.save_to_file(cves)
    else:
        print("No CVEs fetched. Check your internet connection.")