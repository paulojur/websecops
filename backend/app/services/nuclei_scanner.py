import subprocess
import json
import uuid
import threading
import time
from typing import Dict, Any

class NucleiScanner:
    def __init__(self):
        # In-memory store for scans: { scan_id: { "status": "running"|"completed"|"error", "progress": int, "alerts": [] } }
        self._scans: Dict[str, Dict[str, Any]] = {}

    def start_scan(self, target_url: str) -> Dict[str, Any]:
        scan_id = str(uuid.uuid4())
        self._scans[scan_id] = {
            "status": "scanning",
            "progress": 0,
            "alerts": [],
            "details": "Initializing Nuclei engine..."
        }

        # Start the background thread
        thread = threading.Thread(target=self._run_nuclei, args=(scan_id, target_url))
        thread.start()

        return {"status": "started", "scan_id": scan_id, "type": "nuclei"}

    def _run_nuclei(self, scan_id: str, target_url: str):
        # We use -jsonl to get JSON Lines output
        # -silent suppresses banner
        # -v could be used, but we just want results
        command = [
            "nuclei",
            "-u", target_url,
            "-jsonl",
            "-silent"
        ]

        try:
            self._scans[scan_id]["details"] = "Running templates..."
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            alerts = []
            
            # Read stdout line by line as they are found
            if process.stdout:
                for line in iter(process.stdout.readline, ''):
                    if not line:
                        break
                    try:
                        alert = json.loads(line)
                        alerts.append(alert)
                        self._scans[scan_id]["details"] = f"Found: {alert.get('info', {}).get('name', 'Vuln')}"
                    except json.JSONDecodeError:
                        pass
            
            process.wait()

            if process.returncode != 0:
                # If nuclei failed completely (not just found things)
                # Note: nuclei returns 0 usually, but just in case
                stderr_output = process.stderr.read() if process.stderr else ""
                print(f"Nuclei stderr: {stderr_output}")

            self._scans[scan_id]["status"] = "completed"
            self._scans[scan_id]["progress"] = 100
            self._scans[scan_id]["alerts"] = alerts
            self._scans[scan_id]["details"] = "Scan completed."

        except Exception as e:
            self._scans[scan_id]["status"] = "error"
            self._scans[scan_id]["details"] = f"Error: {str(e)}"
            self._scans[scan_id]["progress"] = 0

    def get_progress(self, scan_id: str) -> Dict[str, Any]:
        scan = self._scans.get(scan_id)
        if not scan:
            return {"progress": 0, "details": "Scan not found."}
        
        # Fake progress interpolation since Nuclei doesn't report percentage easily without specific flags
        # If it's still running, we bounce it between 10% and 90%
        if scan["status"] == "scanning":
            scan["progress"] = min(scan["progress"] + 5, 90)

        return {
            "progress": scan["progress"],
            "details": scan["details"],
            "status": scan["status"]
        }

    def get_results(self, scan_id: str) -> Dict[str, Any]:
        scan = self._scans.get(scan_id)
        if not scan:
            return {"alerts": []}
        return {"alerts": scan["alerts"]}
