import os
import requests
import time
from typing import Dict, Any

class ZapScanner:
    def __init__(self):
        self.base_url = "http://zap:8080"
        self.api_key = "secret_api_key" # Matches docker-compose command
        self.headers = {
            "Content-Type": "application/json",
            "X-ZAP-API-Key": self.api_key
        }

    def scan_target(self, target_url: str) -> Dict[str, Any]:
        """
        Initiates a ZAP scan against the target URL.
        Using the 'spider' and 'ascan' (Active Scan) endpoints.
        """
        try:
            print(f"[*] Starting ZAP Spider on {target_url}...")
            # 1. Start Spider
            resp = requests.get(
                f"{self.base_url}/JSON/spider/action/scan/",
                params={"url": target_url, "apikey": self.api_key}
            )
            scan_id = resp.json().get("scan")
            
            if not scan_id:
               return {"status": "error", "message": "Failed to start Spider"}

            # Wait for Spider (simplified for demo)
            # In a real app, we'd use async tasks
            
            print(f"[*] Starting Active Scan on {target_url}...")
            # 2. Start Active Scan
            resp = requests.get(
                f"{self.base_url}/JSON/ascan/action/scan/",
                params={"url": target_url, "apikey": self.api_key}
            )
            ascan_id = resp.json().get("scan")
            
            return {
                "status": "started", 
                "spider_id": scan_id, 
                "ascan_id": ascan_id,
                "message": "Security scan initiated successfully"
            }
            
        except Exception as e:
            print(f"[!] ZAP Connection Error: {e}")
            return {"status": "error", "message": str(e)}

    def get_results(self, base_url: str) -> Dict[str, Any]:
        """
        Get alerts/results for a specific URL
        """
        try:
            resp = requests.get(
                f"{self.base_url}/JSON/core/view/alerts/",
                params={"baseurl": base_url, "apikey": self.api_key}
            )
            return resp.json()
        except Exception as e:
            return {"alerts": []}
