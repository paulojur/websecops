import requests
from typing import List, Dict, Any
from .base import BaseScraper
from datetime import datetime, timedelta, timezone
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class NVDScraper(BaseScraper):
    def __init__(self, api_key: str = None):
        super().__init__("NVD")
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; CyberIntel/1.0; +https://example.com)",
            "Accept": "application/json"
        })
        retries = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"]
        )
        adapter = HTTPAdapter(max_retries=retries)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def _build_date_iso(self, dt: datetime) -> str:
        return dt.replace(tzinfo=timezone.utc).isoformat()

    def _collect_vulnerabilities(self, window_days: int) -> List[Dict[str, Any]]:
        now = datetime.utcnow()
        start_date = now - timedelta(days=window_days)
        base_params = {
            "lastModStartDate": self._build_date_iso(start_date),
            "lastModEndDate": self._build_date_iso(now),
            "resultsPerPage": 200,
        }

        if self.api_key:
            base_params["apiKey"] = self.api_key

        all_vulnerabilities = []
        seen_ids = set()
        start_index = 0
        total_results = 1

        self.logger.info(f"[*] Requesting NVD API for the past {window_days} days")

        while start_index < total_results:
            params = {**base_params, "startIndex": start_index}
            try:
                self.logger.info(f"[*] Requesting NVD API (startIndex={start_index})...")
                response = self.session.get(self.base_url, params=params, timeout=90)
                response.raise_for_status()

                data = response.json()
                total_results = data.get("totalResults", 0)
                items = data.get("vulnerabilities", [])
                self.logger.info(f"    [+] Got {len(items)} items. Total available: {total_results}")

                if not items:
                    break

                parsed = self.parse_data(items)
                for item in parsed:
                    if item["id"] not in seen_ids:
                        seen_ids.add(item["id"])
                        all_vulnerabilities.append(item)

                start_index += len(items)
                if len(all_vulnerabilities) >= 2000:
                    self.logger.info("[!] Reached item limit of 2000. Stopping early.")
                    break
            except requests.exceptions.RequestException as e:
                self.logger.error(f"[!] Exception querying NVD: {e}")
                break
            except ValueError as e:
                self.logger.error(f"[!] JSON decode failed: {e}")
                break

        return all_vulnerabilities

    def fetch_data(self) -> List[Dict[str, Any]]:
        vulnerabilities = self._collect_vulnerabilities(window_days=2)

        if len(vulnerabilities) < 100:
            self.logger.warning("[!] Fewer than 100 CVEs returned for 2 days. Expanding window to 7 days.")
            vulnerabilities = self._collect_vulnerabilities(window_days=7)

        if len(vulnerabilities) < 100:
            self.logger.warning("[!] Fewer than 100 CVEs returned for 7 days. Expanding window to 30 days.")
            vulnerabilities = self._collect_vulnerabilities(window_days=30)

        return vulnerabilities

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
