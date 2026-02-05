import requests
from typing import List, Dict, Any
from .base import BaseScraper
from datetime import datetime, timedelta

class NVDScraper(BaseScraper):
    def __init__(self, api_key: str = None):
        super().__init__("NVD")
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = api_key

    def fetch_data(self) -> List[Dict[str, Any]]:
        # Fetch data modified in the last 10 days
        now = datetime.utcnow()
        yesterday = now - timedelta(days=10)
        
        base_params = {
            "lastModStartDate": yesterday.isoformat(),
            "lastModEndDate": now.isoformat(),
            "resultsPerPage": 2000
        }
        
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        all_vulnerabilities = []
        start_index = 0
        total_results = 1 # Initial dummy value to start loop

        self.logger.info(f"[*] Starting NVD collection (Window: 30 days)")

        while start_index < total_results:
            params = base_params.copy()
            params["startIndex"] = start_index
            
            try:
                self.logger.info(f"[*] Requesting NVD API (startIndex={start_index})...")
                response = requests.get(self.base_url, params=params, headers=headers, timeout=60)
                
                if response.status_code == 200:
                    data = response.json()
                    total_results = data.get("totalResults", 0)
                    items = data.get("vulnerabilities", [])
                    self.logger.info(f"    [+] Got {len(items)} items. Total available: {total_results}")
                    
                    if not items:
                        break
                        
                    all_vulnerabilities.extend(self.parse_data(items))
                    start_index += len(items)
                    
                    # Safety break to avoid infinite loops if something weird happens
                    if len(all_vulnerabilities) > 10000:
                        self.logger.warning("[!] Safety limit reached (10k items). Stopping.")
                        break
                else:
                    self.logger.error(f"[!] NVD API Error: {response.status_code}")
                    break
            except Exception as e:
                self.logger.error(f"[!] Exception querying NVD: {e}")
                break
        
        return all_vulnerabilities

    def parse_data(self, raw_data: Any) -> List[Dict[str, Any]]:
        normalized = []
        # Keywords to filter for Web App Vulnerabilities
        WEB_KEYWORDS = [
            'xss', 'cross-site scripting', 'sql injection', 'sqli', 
            'csrf', 'cross-site request forgery', 'remote code execution', 
            'directory traversal', 'broken access control', 'authentication bypass', 
            'jwt', 'json web token', 'parameter pollution', 'open redirect', 
            'clickjacking', 'php', 'wordpress', 'javascript', 'html', 'http',
            'apache', 'nginx', 'tomcat', 'weblogic', 'flask', 'django', 'node.js'
        ]

        for item in raw_data:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            
            # Extract description
            descriptions = cve.get("descriptions", [])
            desc_text = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")

            # Check if relevant to Web Security
            desc_lower = desc_text.lower()
            if not any(keyword in desc_lower for keyword in WEB_KEYWORDS):
                continue

            # Extract Metrics (CVSS)
            metrics = cve.get("metrics", {})
            cvss_score = 0.0
            severity = "UNKNOWN"
            
            # Try V3.1, then V3.0, then V2
            if "cvssMetricV31" in metrics:
                data = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_score = data.get("baseScore", 0.0)
                severity = data.get("baseSeverity", "UNKNOWN")
            elif "cvssMetricV30" in metrics:
                data = metrics["cvssMetricV30"][0]["cvssData"]
                cvss_score = data.get("baseScore", 0.0)
                severity = data.get("baseSeverity", "UNKNOWN")

            normalized.append({
                "source": "NVD",
                "id": cve_id,
                "title": f"{cve_id} - {severity}",
                "description": desc_text,
                "score": cvss_score,
                "severity": severity,
                "published_date": cve.get("published"),
                "modified_date": cve.get("lastModified"),
                "type": "cve"
            })
        
        return normalized
