import requests
from typing import List, Dict, Any
import logging
from datetime import datetime
import time

class CVESearcher:
    def __init__(self, api_key: str | None = None):
        self.logger = logging.getLogger("cyber_intel.services.cve_searcher")
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = api_key
        # Simple in-memory cache: { "keyword": {"data": [...], "timestamp": float} }
        self.cache = {}
        self.cache_ttl = 3600  # 1 hour cache TTL

    def search(self, keywords: List[str]) -> List[Dict[str, Any]]:
        """
        Searches the NVD API for the given keywords.
        Uses a simple cache to avoid rate limiting.
        """
        results = []
        for keyword in keywords:
            # Check cache
            if keyword in self.cache:
                cached_item = self.cache[keyword]
                if time.time() - cached_item["timestamp"] < self.cache_ttl:
                    self.logger.info(f"[*] Cache hit for '{keyword}'")
                    results.extend(cached_item["data"])
                    continue
                else:
                    del self.cache[keyword]

            # Fetch from API
            self.logger.info(f"[*] Fetching CVEs from NVD API for '{keyword}'")
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": 50, # Limit to top 50 recent results per keyword
            }
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key
                
            try:
                # Be nice to the API if we don't have a key (5 requests / 30 seconds max)
                if not self.api_key:
                    time.sleep(6) # Ensure we don't exceed rate limit of 1 req/6s
                    
                response = requests.get(self.base_url, params=params, headers=headers, timeout=20)
                
                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    parsed_vulns = self._parse_data(vulnerabilities, keyword)
                    
                    # Update cache
                    self.cache[keyword] = {
                        "data": parsed_vulns,
                        "timestamp": time.time()
                    }
                    results.extend(parsed_vulns)
                else:
                    self.logger.error(f"[!] NVD API Error for '{keyword}': {response.status_code}")
                    if response.status_code == 403:
                         self.logger.warning("[!] Rate limit hit on NVD API.")
            except Exception as e:
                 self.logger.error(f"[!] Exception querying NVD API for '{keyword}': {e}")
                 
        # Deduplicate results based on CVE ID
        unique_results = {v["id"]: v for v in results}
        
        # Sort by published date descending
        sorted_results = sorted(unique_results.values(), key=lambda x: x.get("published") or "", reverse=True)
        
        # Return top 50 overall
        return sorted_results[:50]
        
    def _parse_data(self, raw_data: Any, keyword: str) -> List[Dict[str, Any]]:
        normalized = []
        for item in raw_data:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            
            descriptions = cve.get("descriptions", [])
            desc_text = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")

            metrics = cve.get("metrics", {})
            cvss_score = 0.0
            severity = "UNKNOWN"
            
            if "cvssMetricV31" in metrics:
                data = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_score = data.get("baseScore", 0.0)
                severity = data.get("baseSeverity", "UNKNOWN")
            elif "cvssMetricV30" in metrics:
                data = metrics["cvssMetricV30"][0]["cvssData"]
                cvss_score = data.get("baseScore", 0.0)
                severity = data.get("baseSeverity", "UNKNOWN")
            elif "cvssMetricV2" in metrics:
                 data = metrics["cvssMetricV2"][0]["cvssData"]
                 cvss_score = data.get("baseScore", 0.0)
                 severity = data.get("baseSeverity", "UNKNOWN")

            normalized.append({
                "id": cve_id,
                "title": f"{cve_id} - {severity}",
                "description": desc_text,
                "score": cvss_score,
                "severity": severity,
                "published": cve.get("published"),
                "modified_date": cve.get("lastModified"),
                "matched_keyword": keyword
            })
        
        return normalized
