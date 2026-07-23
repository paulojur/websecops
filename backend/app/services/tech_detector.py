import json
import os
import re
import subprocess
from typing import Dict, Any

class TechDetector:
    """
    High-precision hybrid technology stack detector.
    Combines:
    1. Deep HTTP response inspection (Headers, Cookies, Meta, Scripts).
    2. Nuclei Tech Detection templates (if available).
    3. Unlocked dynamic WhatWeb JSON plugin parser.
    """

    def _add_tech(
        self,
        tech_stack: Dict[str, Any],
        name: str,
        version: str | None = None,
        category: str = "Detected",
    ) -> None:
        if not name:
            return
        name_clean = name.strip()
        if name_clean and name_clean not in tech_stack:
            tech_stack[name_clean] = {"version": version, "category": category}

    def _extract_version(self, text: str) -> str | None:
        if not text:
            return None
        match = re.search(r"([0-9]+(?:\.[0-9]+)+)", text)
        return match.group(1) if match else None

    # 1. Deep HTTP & HTML Heuristics Parser
    def _deep_http_heuristics(self, url: str) -> Dict[str, Any]:
        tech_stack: Dict[str, Any] = {}
        try:
            import requests

            response = requests.get(
                url,
                timeout=10,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebSecOps/2.1"}
            )
            html = response.text
            html_low = html.lower()
            headers = {k.lower(): v for k, v in response.headers.items()}
            cookies = {k.lower(): v for k, v in response.cookies.items()}

            server = headers.get("server", "")
            powered_by = headers.get("x-powered-by", "")
            combined_hdrs = f"{server} {powered_by}".lower()

            # Java / Tomcat / Servlet heuristics
            if "jsessionid" in cookies or "jsessionid" in html_low or "jsessionid" in str(response.history):
                self._add_tech(tech_stack, "Java", None, "Programming Language")
                self._add_tech(tech_stack, "Apache Tomcat", self._extract_version(server), "Web Server")
            elif "coyote" in combined_hdrs or "tomcat" in combined_hdrs:
                self._add_tech(tech_stack, "Apache Tomcat", self._extract_version(server) or self._extract_version(powered_by), "Web Server")
                self._add_tech(tech_stack, "Java", None, "Programming Language")
            elif "servlet" in combined_hdrs or "jsp" in combined_hdrs:
                self._add_tech(tech_stack, "Java", None, "Programming Language")
                self._add_tech(tech_stack, "Java Servlet", self._extract_version(powered_by), "Web Framework")

            # PHP / CMS / Frameworks
            if "phpsessid" in cookies or "php" in powered_by.lower():
                self._add_tech(tech_stack, "PHP", self._extract_version(powered_by), "Programming Language")

            if "wordpress" in html_low or "wp-content" in html_low or "wp-json" in html_low:
                self._add_tech(tech_stack, "WordPress", self._extract_version(html_low), "CMS")
            if "shopify" in html_low or "cdn.shopify.com" in html_low:
                self._add_tech(tech_stack, "Shopify", None, "E-commerce")
            if "drupal" in html_low or "drupal.js" in html_low:
                self._add_tech(tech_stack, "Drupal", None, "CMS")
            if "joomla" in html_low:
                self._add_tech(tech_stack, "Joomla", None, "CMS")

            # JavaScript Frameworks & Libraries
            if "goober" in html_low or "goober.js" in html_low:
                self._add_tech(tech_stack, "Goober", None, "JavaScript Library")
            if "react" in html_low or "__next" in html_low or "react-dom" in html_low:
                self._add_tech(tech_stack, "React", None, "JavaScript Framework")
            if "next.js" in html_low or "__next" in html_low:
                self._add_tech(tech_stack, "Next.js", None, "JavaScript Framework")
            if "angular" in html_low or "ng-version" in html_low:
                self._add_tech(tech_stack, "Angular", None, "JavaScript Framework")
            if "vue" in html_low or "v-data-" in html_low or "vue.js" in html_low:
                self._add_tech(tech_stack, "Vue.js", None, "JavaScript Framework")
            if "jquery" in html_low or "jquery.min.js" in html_low:
                self._add_tech(tech_stack, "jQuery", self._extract_version(html_low), "JavaScript Library")
            if "bootstrap" in html_low or "bootstrap.min.css" in html_low:
                self._add_tech(tech_stack, "Bootstrap", self._extract_version(html_low), "CSS Framework")

            # Web Servers & OS
            if "apache" in server.lower():
                if "Apache Tomcat" not in tech_stack:
                    self._add_tech(tech_stack, "Apache", self._extract_version(server), "Web Server")
            if "nginx" in server.lower():
                self._add_tech(tech_stack, "Nginx", self._extract_version(server), "Web Server")
            if "iis" in server.lower() or "asp.net" in powered_by.lower():
                self._add_tech(tech_stack, "IIS", self._extract_version(server), "Web Server")
                self._add_tech(tech_stack, "ASP.NET", self._extract_version(powered_by), "Programming Language")
            if "gunicorn" in server.lower() or "gunicorn" in powered_by.lower():
                self._add_tech(tech_stack, "Gunicorn", self._extract_version(server) or self._extract_version(powered_by), "Web Server")

            if any(tok in combined_hdrs or tok in html_low for tok in ["ubuntu", "debian", "centos", "fedora", "redhat", "alpine", "linux"]):
                self._add_tech(tech_stack, "Linux", None, "Operating System")

        except Exception as exc:
            print(f"[!] Deep HTTP heuristics error: {exc}")

        return tech_stack

    # 2. Nuclei Technology Detection Engine
    def _nuclei_tech_detection(self, url: str) -> Dict[str, Any]:
        tech_stack: Dict[str, Any] = {}
        try:
            cmd = [
                "nuclei",
                "-u", url,
                "-t", "http/technologies/",
                "-jsonl",
                "-silent",
                "-timeout", "5",
                "-concurrency", "5"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if res.stdout:
                for line in res.stdout.strip().split("\n"):
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                        info = data.get("info", {})
                        name = info.get("name") or data.get("template-id")
                        extracted = data.get("extracted-results", [])
                        version = extracted[0] if extracted else None
                        if name:
                            clean_name = name.replace("-detect", "").replace("-check", "").title()
                            self._add_tech(tech_stack, clean_name, version, "Detected by Nuclei")
                    except Exception:
                        pass
        except FileNotFoundError:
            pass
        except Exception as exc:
            print(f"[!] Nuclei tech detection skipped: {exc}")

        return tech_stack

    # WhatWeb plugins that are HTTP attributes or meta info, not software technologies
    IGNORED_PLUGINS = {
        "Country", "IP", "Title", "Unassigned", "HTML5", "Cookies", "HttpOnly",
        "Secure", "MetaGenerator", "X-UA-Compatible", "Strict-Transport-Security",
        "Content-Security-Policy", "OpenGraph", "Script", "Header", "RedirectLocation",
        "String", "HTTPServer", "X-Powered-By", "X-Frame-Options", "X-XSS-Protection",
        "X-Content-Type-Options", "Set-Cookie", "Frame"
    }

    # 3. Unlocked Dynamic WhatWeb Plugin Parser
    def _parse_whatweb_json(self, raw_json: str) -> Dict[str, Any]:
        tech_stack: Dict[str, Any] = {}
        try:
            entries = json.loads(raw_json)
            if not isinstance(entries, list) or not entries:
                return tech_stack
            plugins: Dict[str, Any] = entries[0].get("plugins", {})
            for plugin_name, plugin_data in plugins.items():
                if plugin_name in self.IGNORED_PLUGINS:
                    # Parse HTTPServer and X-Powered-By specifically for software name
                    if plugin_name == "HTTPServer":
                        strings = plugin_data.get("string", [])
                        string_val = str(strings[0]) if strings else ""
                        low = string_val.lower()
                        if "apache-coyote" in low or "coyote" in low:
                            self._add_tech(tech_stack, "Apache Tomcat", self._extract_version(string_val), "Web Server")
                        elif "nginx" in low:
                            self._add_tech(tech_stack, "Nginx", self._extract_version(string_val), "Web Server")
                        elif "apache" in low and "Apache Tomcat" not in tech_stack:
                            self._add_tech(tech_stack, "Apache", self._extract_version(string_val), "Web Server")
                        elif "iis" in low:
                            self._add_tech(tech_stack, "IIS", self._extract_version(string_val), "Web Server")
                    elif plugin_name == "X-Powered-By":
                        strings = plugin_data.get("string", [])
                        string_val = str(strings[0]) if strings else ""
                        low = string_val.lower()
                        if "php" in low:
                            self._add_tech(tech_stack, "PHP", self._extract_version(string_val), "Programming Language")
                        elif "servlet" in low or "jsp" in low:
                            self._add_tech(tech_stack, "Java Servlet", self._extract_version(string_val), "Web Framework")
                            self._add_tech(tech_stack, "Java", None, "Programming Language")
                        elif "asp.net" in low:
                            self._add_tech(tech_stack, "ASP.NET", self._extract_version(string_val), "Programming Language")
                    continue

                versions = plugin_data.get("version", [])
                version = str(versions[0]) if versions else None
                strings = plugin_data.get("string", [])
                string_val = str(strings[0]) if strings else ""

                name = plugin_name
                category = "Detected"

                # Category inference for plugins
                if "CMS" in plugin_name or plugin_name in {"WordPress", "Drupal", "Joomla"}:
                    category = "CMS"
                elif plugin_name in {"React", "Angular", "Vue.js", "Next.js", "Nuxt.js"}:
                    category = "JavaScript Framework"
                elif plugin_name in {"jQuery", "Bootstrap", "Tailwind-CSS", "Goober"}:
                    category = "JavaScript Library"
                elif plugin_name in {"PHP", "Python", "Ruby", "Java", "ASP.NET"}:
                    category = "Programming Language"
                elif plugin_name in {"Apache", "Nginx", "IIS", "Lighttpd", "Gunicorn", "Apache Tomcat"}:
                    category = "Web Server"

                self._add_tech(tech_stack, name, version, category)

            # Cleanup duplicates: If Tomcat is present, remove generic Apache
            if "Apache Tomcat" in tech_stack and "Apache" in tech_stack:
                del tech_stack["Apache"]

        except Exception as exc:
            print(f"[!] WhatWeb JSON parse error: {exc}")
        return tech_stack

    def _parse_whatweb_output(self, raw_text: str) -> Dict[str, Any]:
        """Legacy text output parser maintained for unit test backwards compatibility."""
        tech_stack: Dict[str, Any] = {}
        for line in raw_text.splitlines():
            if "WordPress" in line:
                self._add_tech(tech_stack, "WordPress", self._extract_version(line), "CMS")
            if "Nginx" in line or "nginx" in line:
                self._add_tech(tech_stack, "Nginx", self._extract_version(line), "Web Server")
            if "PHP" in line:
                self._add_tech(tech_stack, "PHP", self._extract_version(line), "Programming Language")
            if "Apache" in line:
                self._add_tech(tech_stack, "Apache", self._extract_version(line), "Web Server")
            if "Tomcat" in line:
                self._add_tech(tech_stack, "Apache Tomcat", self._extract_version(line), "Web Server")
            if "Java" in line:
                self._add_tech(tech_stack, "Java", None, "Programming Language")
        return tech_stack

    def _whatweb_detection(self, url: str) -> Dict[str, Any]:
        import tempfile
        try:
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
                tmp_name = tmp.name

            try:
                result = subprocess.run(
                    ["whatweb", "-q", "--color=never", f"--log-json={tmp_name}", url],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                
                with open(tmp_name, 'r', encoding='utf-8') as f:
                    output = f.read().strip()
                    
                if output:
                    parsed = self._parse_whatweb_json(output)
                    if parsed:
                        return parsed
            finally:
                if os.path.exists(tmp_name):
                    os.remove(tmp_name)
        except Exception as exc:
            print(f"[!] WhatWeb detection exception: {exc}")
        return {}

    def detect(self, url: str) -> Dict[str, Any]:
        """
        Executes hybrid technology detection: Deep HTTP Heuristics + Nuclei + WhatWeb.
        Combines all sources into a unified, rich technology map.
        """
        combined_stack: Dict[str, Any] = {}

        # 1. Deep HTTP Heuristics (Always runs fast)
        http_results = self._deep_http_heuristics(url)
        combined_stack.update(http_results)

        # 2. WhatWeb Detection (If available)
        whatweb_results = self._whatweb_detection(url)
        combined_stack.update(whatweb_results)

        # 3. Nuclei Tech Detection (If available)
        nuclei_results = self._nuclei_tech_detection(url)
        combined_stack.update(nuclei_results)

        print(f"[+] Total technologies detected for {url}: {len(combined_stack)}")
        return combined_stack
