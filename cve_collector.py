"""
CVE Data Collector Module
Fetches vulnerability data from NIST NVD API and CISA KEV Catalog.
Extracts vendor patch links for actionable remediation.
"""

import requests
import json
import os
from datetime import datetime, timedelta
import logging
from typing import List, Dict, Set

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CVEDataCollector:
    """
    Collector for security vulnerability data from multiple sources.
    1. NIST NVD (National Vulnerability Database)
    2. CISA KEV (Known Exploited Vulnerabilities)
    """
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cisa_kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def fetch_cisa_kev(self) -> Set[str]:
        """Fetch CISA Known Exploited Vulnerabilities"""
        try:
            logger.info("Fetching CISA KEV data...")
            response = requests.get(self.cisa_kev_url, timeout=15)
            response.raise_for_status()
            data = response.json()
            kev_cves = {v['cveID'] for v in data.get('vulnerabilities', [])}
            logger.info(f"Loaded {len(kev_cves)} exploited vulnerabilities from CISA KEV.")
            return kev_cves
        except Exception as e:
            logger.error(f"Failed to fetch CISA KEV: {e}")
            return set()

    def fetch_recent_cves(self, days: int = 90, max_results: int = 500) -> List[Dict]:
        """Fetch NVD data and enrich with References (Patch Links)"""
        kev_set = self.fetch_cisa_kev()
        
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        pub_start = start_date.strftime('%Y-%m-%dT%H:%M:%S.000')
        pub_end = end_date.strftime('%Y-%m-%dT%H:%M:%S.000')
        
        params = {
            'pubStartDate': pub_start,
            'pubEndDate': pub_end,
            'resultsPerPage': max_results
        }
        
        headers = {}
        if self.api_key:
            headers['apiKey'] = self.api_key
            
        try:
            logger.info(f"Fetching NVD CVEs from {start_date.date()} to {end_date.date()}...")
            response = requests.get(self.nvd_base_url, params=params, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            cve_items = data.get('vulnerabilities', [])
            logger.info(f"Fetched {len(cve_items)} CVEs from NVD.")
            
            processed_cves = []
            
            for item in cve_items:
                cve = item['cve']
                cve_id = cve['id']
                
                # 1. Description
                descriptions = cve.get('descriptions', [])
                desc_text = next((d['value'] for d in descriptions if d['lang'] == 'en'), "No description available.")
                
                # 2. Metrics (Severity)
                metrics = cve.get('metrics', {})
                severity = "UNKNOWN"
                if 'cvssMetricV31' in metrics:
                    severity = metrics['cvssMetricV31'][0]['cvssData'].get('baseSeverity', 'UNKNOWN')
                elif 'cvssMetricV30' in metrics:
                    severity = metrics['cvssMetricV30'][0]['cvssData'].get('baseSeverity', 'UNKNOWN')
                elif 'cvssMetricV2' in metrics:
                    severity = metrics['cvssMetricV2'][0].get('baseSeverity', 'UNKNOWN')
                
                # 3. References (Patch Links) - NEW FEATURE
                refs = cve.get('references', [])
                patch_links = [r['url'] for r in refs if 'url' in r][:3] # Keep top 3 links to save tokens
                
                # 4. Enrichment
                is_exploited = cve_id in kev_set
                cisa_tag = "[⚠️ CISA KEV: EXPLOITED IN WILD]" if is_exploited else ""
                
                # Format references for Embedding
                ref_text = "\nReferences: " + ", ".join(patch_links) if patch_links else ""
                
                processed_cves.append({
                    'id': cve_id,
                    'description': desc_text,
                    'severity': severity,
                    'published': cve.get('published', ''),
                    'source': 'nvd',
                    'is_exploited': is_exploited,
                    'cisa_warning': cisa_tag,
                    'references': patch_links, # Store list for UI if needed
                    # Content field is what the LLM sees
                    'content': f"{cve_id} {cisa_tag}\nSeverity: {severity}\nDescription: {desc_text}{ref_text}"
                })
                
            return processed_cves
            
        except Exception as e:
            logger.error(f"Error fetching CVEs: {e}")
            return []

    def save_to_file(self, data: List[Dict], filename: str = "data/cve_data.json"):
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info(f"Saved {len(data)} records to {filename}")

    def load_from_file(self, filename: str = "data/cve_data.json") -> List[Dict]:
        if not os.path.exists(filename):
            return []
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)