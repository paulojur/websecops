import os
import requests
import time
from typing import Dict, Any, Optional
import logging

class ZapScanner:
    def __init__(self):
        self.logger = logging.getLogger("cyber_intel.services.zap_scanner")
        self.base_url = "http://zap:8080"
        self.api_key = "secret_api_key" 
        self.headers = {
            "Content-Type": "application/json",
            "X-ZAP-API-Key": self.api_key
        }

    def start_spider(self, target_url: str) -> Dict[str, Any]:
        """
        Starts a classic Spider scan (Crawling).
        This is PASSIVE in terms of attacks, but active in terms of traffic.
        """
        try:
            print(f"[*] Starting ZAP Spider on {target_url}...")
            resp = requests.get(
                f"{self.base_url}/JSON/spider/action/scan/",
                params={"url": target_url, "apikey": self.api_key}
            )
            data = resp.json()
            scan_id = data.get("scan")
            if not scan_id:
                self.logger.error(f"Failed to start Spider: {data}")
                return {"status": "error", "message": "Failed to start Spider", "raw": data}
            
            self.logger.info(f"Spider started with ID: {scan_id}")
            return {"status": "started", "scan_id": scan_id, "type": "spider"}
        except Exception as e:
            self.logger.error(f"Exception starting Spider: {e}")
            return {"status": "error", "message": str(e)}

    def start_active_scan(self, target_url: str) -> Dict[str, Any]:
        """
        Starts an Active Scan (Attack).
        Constructive, but intrusive.
        """
        try:
            print(f"[*] Starting ZAP Active Scan on {target_url}...")
            # Ideally we check if spider is done first, but ZAP handles queueing or we handle it in orchestration
            resp = requests.get(
                f"{self.base_url}/JSON/ascan/action/scan/",
                params={"url": target_url, "apikey": self.api_key, "recurse": "true"}
            )
            data = resp.json()
            
            # Check for URL Not Found error (needs Spider first)
            if data.get("code") == "url_not_found":
                self.logger.warning(f"Target {target_url} not found in scan tree. active scan aborted.")
                return {"status": "error", "message": "Target not crawled. Please run a Spider Scan (Passive) first."}

            scan_id = data.get("scan")
            if not scan_id:
                self.logger.error(f"Failed to start Active Scan: {data}")
                return {"status": "error", "message": "Failed to start Active Scan", "raw": data}
            
            self.logger.info(f"Active Scan started with ID: {scan_id}")
            return {"status": "started", "scan_id": scan_id, "type": "active_scan"}
        except Exception as e:
            self.logger.error(f"Exception starting Active Scan: {e}")
            return {"status": "error", "message": str(e)}

    def get_progress(self, scan_id: str, scan_type: str = "spider") -> Dict[str, Any]:
        """
        Get progress and detailed current status.
        Returns: {"progress": int, "details": str}
        """
        try:
            endpoint = "spider" if scan_type == "spider" else "ascan"
            
            # 1. Get numeric status (0-100)
            resp = requests.get(
                f"{self.base_url}/JSON/{endpoint}/view/status/",
                params={"scanId": scan_id, "apikey": self.api_key},
                timeout=5
            )
            progress = int(resp.json().get("status", "0"))
            
            # 2. Get verbose details (What is currently being scanned?)
            details = "Scanning..."
            if scan_type == "ascan":
                # Active scan has detailed progress per plugin
                try:
                    p_resp = requests.get(
                         f"{self.base_url}/JSON/ascan/view/scanProgress/",
                         params={"scanId": scan_id, "apikey": self.api_key},
                         timeout=5
                    )
                    plugins = p_resp.json().get("scanProgress", [])[1].get("HostProcess", [])
                    # Find running plugins
                    running = [p for p in plugins if p.get("status") == "RUNNING"]
                    if running:
                        plugin_name = running[0].get("Plugin", ["Unknown"])[0]
                        details = f"Testing: {plugin_name}"
                    elif progress < 100:
                        details = "Initializing attack vectors..."
                    else:
                        details = "Finalizing report..."
                except:
                    details = "Active Scan running..."
            elif scan_type == "spider":
                # Spider just crawls
                if progress < 100:
                   details = f"Crawling site map... ({progress}%)"
                else:
                   details = "Crawling completed."

            return {"progress": progress, "details": details}
        except Exception as e:
            return {"progress": 0, "details": f"Error: {str(e)}"}

    def get_alerts(self, base_url: str) -> Dict[str, Any]:
        """
        Get all alerts for a target.
        Handles protocol mismatches (http vs https) by checking ZAP's known sites if direct fetch fails.
        """
        try:
            # 1. Try direct fetch
            resp = requests.get(
                f"{self.base_url}/JSON/core/view/alerts/",
                params={"baseurl": base_url, "apikey": self.api_key},
                timeout=10
            )
            data = resp.json()
            alerts = data.get("alerts", [])
            
            # 2. If no alerts, check if we have them under a slightly different URL (http vs https)
            if not alerts:
                # Get all sites ZAP knows about
                sites_resp = requests.get(
                    f"{self.base_url}/JSON/core/view/sites/",
                    params={"apikey": self.api_key},
                    timeout=5
                )
                sites = sites_resp.json().get("sites", [])
                
                # Normalize target URL for comparison (remove protocol and trailing slash)
                target_domain = base_url.replace("http://", "").replace("https://", "").rstrip("/")
                
                # Find matching site in ZAP
                matching_site = None
                for site in sites:
                    site_domain = site.replace("http://", "").replace("https://", "").rstrip("/")
                    if site_domain == target_domain:
                        matching_site = site
                        break
                
                if matching_site and matching_site != base_url:
                    print(f"[*] Redirect/Protocol mismatch detected. Fetching alerts for {matching_site} instead of {base_url}")
                    resp = requests.get(
                        f"{self.base_url}/JSON/core/view/alerts/",
                        params={"baseurl": matching_site, "apikey": self.api_key},
                        timeout=10
                    )
                    return resp.json()

            return data
        except Exception as e:
            print(f"Error fetching alerts: {e}")
            return {"alerts": []}

    def get_full_report(self, base_url: str, alerts: list) -> Dict[str, Any]:
        """
        Generates a PASS/FAIL report by comparing all active AND passive scan rules 
        against found alerts.
        """
        try:
            alert_names = {a.get("alert") for a in alerts}
            report = []
            
            # Helper to process scanners
            def process_scanners(scanners_list, scan_type):
                for scanner in scanners_list:
                    name = scanner.get("name")
                    # Check if this scanner alerted
                    status = "fail" if name in alert_names else "pass"
                    report.append({
                        "name": name,
                        "status": status,
                        "cwe": scanner.get("cweId"),
                        "type": scan_type
                    })

            # 1. Get Active Scanners
            try:
                scanners_resp = requests.get(
                    f"{self.base_url}/JSON/ascan/view/scanners/",
                    params={"apikey": self.api_key},
                    timeout=10
                )
                active_scanners = scanners_resp.json().get("scanners", [])
                process_scanners(active_scanners, "active")
            except Exception as e:
                self.logger.error(f"Failed to fetch active scanners: {e}")

            # 2. Get Passive Scanners
            try:
                pscan_resp = requests.get(
                    f"{self.base_url}/JSON/pscan/view/scanners/",
                    params={"apikey": self.api_key},
                    timeout=10
                )
                passive_scanners = pscan_resp.json().get("scanners", [])
                process_scanners(passive_scanners, "passive")
            except Exception as e:
                self.logger.error(f"Failed to fetch passive scanners: {e}")
                
            return {"coverage": report}
        except Exception as e:
            return {"coverage": [], "error": str(e)}
