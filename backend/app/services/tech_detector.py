import json
import os
import re
import subprocess
from typing import Dict, Any

class TechDetector:
    """
    Detects technologies using Wappalyzer API when configured and falls back to
    richer HTTP heuristics for real-world targets.
    """

    def _add_tech(self, tech_stack: Dict[str, Any], name: str, version: str | None = None, category: str = "Detected") -> None:
        if name and name not in tech_stack:
            tech_stack[name] = {"version": version, "category": category}

    def _extract_version(self, text: str) -> str | None:
        if not text:
            return None
        match = re.search(r"([0-9]+(?:\.[0-9]+)+)", text)
        return match.group(1) if match else None

    def _parse_whatweb_output(self, raw_output: str) -> Dict[str, Any]:
        """Parse WhatWeb output into a normalized technology map."""
        tech_stack: Dict[str, Any] = {}
        if not raw_output:
            return tech_stack

        lower_output = raw_output.lower()
        lines = [line.strip() for line in raw_output.splitlines() if line.strip()]

        for line in lines:
            if line.startswith("[") and "]" in line:
                continue

            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()
            else:
                key = ""
                value = line

            if not value:
                continue

            if "wordpress" in value.lower():
                version = self._extract_version(value)
                self._add_tech(tech_stack, "WordPress", version, "CMS")
            elif "shopify" in value.lower():
                self._add_tech(tech_stack, "Shopify", None, "E-commerce")
            elif "react" in value.lower():
                self._add_tech(tech_stack, "React", None, "JavaScript Framework")
            elif "angular" in value.lower():
                self._add_tech(tech_stack, "Angular", None, "JavaScript Framework")
            elif "vue" in value.lower():
                self._add_tech(tech_stack, "Vue.js", None, "JavaScript Framework")
            elif "bootstrap" in value.lower():
                self._add_tech(tech_stack, "Bootstrap", None, "CSS Framework")
            elif "jquery" in value.lower():
                self._add_tech(tech_stack, "jQuery", None, "JavaScript Library")
            elif "nginx" in value.lower():
                self._add_tech(tech_stack, "Nginx", self._extract_version(value), "Web Server")
            elif "apache" in value.lower():
                self._add_tech(tech_stack, "Apache", self._extract_version(value), "Web Server")
            elif "php" in value.lower():
                self._add_tech(tech_stack, "PHP", self._extract_version(value), "Programming Language")
            elif "linux" in value.lower():
                self._add_tech(tech_stack, "Linux", None, "Operating System")
            elif "windows" in value.lower():
                self._add_tech(tech_stack, "Windows", None, "Operating System")

            if key.lower() in {"httpserver", "x-powered-by", "server"}:
                lowered_value = value.lower()
                if "nginx" in lowered_value:
                    self._add_tech(tech_stack, "Nginx", self._extract_version(value), "Web Server")
                if "apache" in lowered_value:
                    self._add_tech(tech_stack, "Apache", self._extract_version(value), "Web Server")
                if "php" in lowered_value:
                    self._add_tech(tech_stack, "PHP", self._extract_version(value), "Programming Language")

        if not tech_stack and lower_output:
            self._add_tech(tech_stack, "HTML", None, "Markup Language")

        return tech_stack

    def _whatweb_detection(self, url: str) -> Dict[str, Any]:
        """Try WhatWeb, which is open source and free, as a richer fingerprinting source."""
        try:
            result = subprocess.run(
                ["whatweb", "--color=never", url],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode == 0 and result.stdout.strip():
                return self._parse_whatweb_output(result.stdout)
            if result.stderr:
                print(f"[!] WhatWeb error: {result.stderr.strip()}")
        except FileNotFoundError:
            print("[!] WhatWeb is not installed in the container")
        except Exception as exc:
            print(f"[!] WhatWeb detection failed: {exc}")
        return {}

    def _fallback_detection(self, url: str) -> Dict[str, Any]:
        """Simple heuristic fallback when Wappalyzer/WhatWeb are unavailable or return nothing."""
        tech_stack: Dict[str, Any] = {}
        try:
            import requests

            response = requests.get(url, timeout=10)
            html = response.text.lower()
            headers = response.headers
            server = headers.get("server", "") or ""
            powered_by = headers.get("x-powered-by", "") or ""
            combined = f"{html} {server} {powered_by}".lower()

            if "wordpress" in combined or "wp-content" in combined or "wp-json" in combined:
                self._add_tech(tech_stack, "WordPress", None, "CMS")
            if "shopify" in combined or "cdn.shopify.com" in combined:
                self._add_tech(tech_stack, "Shopify", None, "E-commerce")
            if "react" in combined or "__next" in combined:
                self._add_tech(tech_stack, "React", None, "JavaScript Framework")
            if "angular" in combined:
                self._add_tech(tech_stack, "Angular", None, "JavaScript Framework")
            if "vue" in combined:
                self._add_tech(tech_stack, "Vue.js", None, "JavaScript Framework")
            if "bootstrap" in combined:
                self._add_tech(tech_stack, "Bootstrap", None, "CSS Framework")
            if "jquery" in combined:
                self._add_tech(tech_stack, "jQuery", None, "JavaScript Library")
            if "apache" in server.lower() or "apache" in powered_by.lower():
                self._add_tech(tech_stack, "Apache", self._extract_version(server) or self._extract_version(powered_by), "Web Server")
            if "nginx" in server.lower() or "nginx" in powered_by.lower():
                self._add_tech(tech_stack, "Nginx", self._extract_version(server) or self._extract_version(powered_by), "Web Server")
            if "gunicorn" in server.lower() or "gunicorn" in powered_by.lower():
                self._add_tech(tech_stack, "Gunicorn", self._extract_version(server) or self._extract_version(powered_by), "Web Server")
            if "php" in powered_by.lower():
                self._add_tech(tech_stack, "PHP", self._extract_version(powered_by), "Programming Language")
            if "asp.net" in powered_by.lower():
                self._add_tech(tech_stack, "ASP.NET", self._extract_version(powered_by), "Programming Language")
            if any(token in combined for token in ["ubuntu", "debian", "centos", "fedora", "red hat", "alpine", "linux"]):
                self._add_tech(tech_stack, "Linux", None, "Operating System")
            if any(token in combined for token in ["windows", "iis", "microsoft", "asp.net"]):
                self._add_tech(tech_stack, "Windows", None, "Operating System")
            if "freebsd" in combined:
                self._add_tech(tech_stack, "FreeBSD", None, "Operating System")
            if "text/html" in (headers.get("content-type", "") or "").lower():
                self._add_tech(tech_stack, "HTML", None, "Markup Language")
        except Exception as exc:
            print(f"[!] Fallback detection failed: {exc}")

        return tech_stack

    def detect(self, url: str) -> Dict[str, Any]:
        """Detects technologies using Wappalyzer API when configured, otherwise falls back to HTTP heuristics."""
        tech_stack: Dict[str, Any] = {}
        try:
            api_key = os.getenv("WAPPALYZER_API_KEY")
            if api_key:
                print(f"[*] Running Wappalyzer API detection for {url}...")
                import requests

                response = requests.post(
                    "https://api.wappalyzer.com/lookup",
                    headers={"x-api-key": api_key},
                    json={"url": url},
                    timeout=30,
                )
                response.raise_for_status()
                payload = response.json()
                for tech in payload.get("technologies", []):
                    name = tech.get("name") or tech.get("slug")
                    if name:
                        tech_stack[name] = {"version": None, "category": "Detected by Wappalyzer"}
                if tech_stack:
                    print(f"[+] Found {len(tech_stack)} technologies on {url} via Wappalyzer API.")
                    return tech_stack

            print(f"[*] Running WhatWeb-based technology detection for {url}...")
            whatweb_result = self._whatweb_detection(url)
            if whatweb_result:
                print(f"[+] Found {len(whatweb_result)} technologies on {url} via WhatWeb.")
                return whatweb_result

            print(f"[*] Running HTTP-based technology detection for {url}...")
            return self._fallback_detection(url)

        except Exception as e:
            print(f"[!] Detection Error: {e}")
            return {}

if __name__ == "__main__":
    detector = TechDetector()
    print(json.dumps(detector.detect("https://example.com"), indent=2))
