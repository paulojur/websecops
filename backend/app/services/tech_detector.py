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

    # Maps WhatWeb plugin names → (normalized name, category)
    _WHATWEB_PLUGIN_MAP: Dict[str, tuple] = {
        "WordPress":        ("WordPress",       "CMS"),
        "Drupal":           ("Drupal",          "CMS"),
        "Joomla":           ("Joomla",          "CMS"),
        "Shopify":          ("Shopify",         "E-commerce"),
        "WooCommerce":      ("WooCommerce",     "E-commerce"),
        "Magento":          ("Magento",         "E-commerce"),
        "PrestaShop":       ("PrestaShop",      "E-commerce"),
        "React":            ("React",           "JavaScript Framework"),
        "Angular":          ("Angular",         "JavaScript Framework"),
        "AngularJS":        ("AngularJS",       "JavaScript Framework"),
        "Vue.js":           ("Vue.js",          "JavaScript Framework"),
        "Next.js":          ("Next.js",         "JavaScript Framework"),
        "Nuxt.js":          ("Nuxt.js",         "JavaScript Framework"),
        "jQuery":           ("jQuery",          "JavaScript Library"),
        "Bootstrap":        ("Bootstrap",       "CSS Framework"),
        "Tailwind-CSS":     ("Tailwind CSS",    "CSS Framework"),
        "Apache":           ("Apache",          "Web Server"),
        "Nginx":            ("Nginx",           "Web Server"),
        "IIS":              ("IIS",             "Web Server"),
        "Lighttpd":         ("Lighttpd",        "Web Server"),
        "Caddy":            ("Caddy",           "Web Server"),
        "Gunicorn":         ("Gunicorn",        "Web Server"),
        "uWSGI":            ("uWSGI",           "Web Server"),
        "PHP":              ("PHP",             "Programming Language"),
        "Python":           ("Python",          "Programming Language"),
        "Ruby":             ("Ruby",            "Programming Language"),
        "ASP.NET":          ("ASP.NET",         "Programming Language"),
        "Java":             ("Java",            "Programming Language"),
        "Node.js":          ("Node.js",         "Runtime"),
        "Django":           ("Django",          "Web Framework"),
        "Laravel":          ("Laravel",         "Web Framework"),
        "Ruby-on-Rails":    ("Ruby on Rails",   "Web Framework"),
        "Express":          ("Express",         "Web Framework"),
        "Flask":            ("Flask",           "Web Framework"),
        "FastAPI":          ("FastAPI",         "Web Framework"),
        "MySQL":            ("MySQL",           "Database"),
        "PostgreSQL":       ("PostgreSQL",      "Database"),
        "MongoDB":          ("MongoDB",         "Database"),
        "Redis":            ("Redis",           "Database"),
        "Ubuntu":           ("Ubuntu",          "Operating System"),
        "Debian":           ("Debian",          "Operating System"),
        "CentOS":           ("CentOS",          "Operating System"),
        "HTTPServer":       None,  # handled separately (contains server string)
        "X-Powered-By":     None,  # handled separately
        "Cloudflare":       ("Cloudflare",      "CDN / WAF"),
        "Fastly":           ("Fastly",          "CDN"),
        "Varnish":          ("Varnish",         "Cache"),
        "Google-Analytics": ("Google Analytics","Analytics"),
        "Facebook":         ("Facebook Pixel",  "Analytics"),
        "reCAPTCHA":        ("reCAPTCHA",       "Security"),
        "Let's-Encrypt":    ("Let's Encrypt",   "SSL/TLS"),
    }

    def _parse_whatweb_json(self, raw_json: str) -> Dict[str, Any]:
        """Parse WhatWeb --log-json output into a normalized technology map."""
        tech_stack: Dict[str, Any] = {}
        try:
            entries = json.loads(raw_json)
            if not isinstance(entries, list) or not entries:
                return tech_stack
            plugins: Dict[str, Any] = entries[0].get("plugins", {})
            for plugin_name, plugin_data in plugins.items():
                mapping = self._WHATWEB_PLUGIN_MAP.get(plugin_name)

                # Plugins handled separately to extract version from string value
                if plugin_name in {"HTTPServer", "X-Powered-By"}:
                    strings = plugin_data.get("string", [])
                    value = strings[0] if strings else ""
                    low = value.lower()
                    if "nginx" in low:
                        self._add_tech(tech_stack, "Nginx", self._extract_version(value), "Web Server")
                    if "apache" in low:
                        self._add_tech(tech_stack, "Apache", self._extract_version(value), "Web Server")
                    if "php" in low:
                        self._add_tech(tech_stack, "PHP", self._extract_version(value), "Programming Language")
                    if "gunicorn" in low:
                        self._add_tech(tech_stack, "Gunicorn", self._extract_version(value), "Web Server")
                    if "iis" in low:
                        self._add_tech(tech_stack, "IIS", self._extract_version(value), "Web Server")
                    continue

                if mapping is None:
                    continue  # explicitly unmapped, skip

                if mapping:
                    name, category = mapping
                    versions = plugin_data.get("version", [])
                    version = versions[0] if versions else None
                    self._add_tech(tech_stack, name, version, category)
        except (json.JSONDecodeError, KeyError, IndexError) as exc:
            print(f"[!] WhatWeb JSON parse error: {exc}")
        return tech_stack

    def _whatweb_detection(self, url: str) -> Dict[str, Any]:
        """Run WhatWeb with JSON output for reliable structured parsing."""
        try:
            result = subprocess.run(
                ["whatweb", "--color=never", "--log-json=/dev/stdout", url],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            output = result.stdout.strip()
            if output:
                parsed = self._parse_whatweb_json(output)
                if parsed:
                    return parsed
            if result.stderr:
                print(f"[!] WhatWeb stderr: {result.stderr.strip()[:200]}")
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
