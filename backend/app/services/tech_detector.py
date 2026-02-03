import requests
from bs4 import BeautifulSoup
from typing import Dict, List, Any

class TechDetector:
    def detect(self, url: str) -> Dict[str, Any]:
        """
        Passively detects technologies from URL headers and HTML content.
        """
        tech_stack = {}
        try:
            # 1. Header Analysis
            print(f"[*] Analyzing headers for {url}...")
            response = requests.get(url, timeout=10, verify=False) # Skip SSL verify for internal testing sites
            headers = response.headers
            
            if 'Server' in headers:
                tech_stack['Server'] = headers['Server']
            
            if 'X-Powered-By' in headers:
                tech_stack['Backend'] = headers['X-Powered-By']
                
            if 'X-AspNet-Version' in headers:
                tech_stack['Framework'] = f"ASP.NET {headers['X-AspNet-Version']}"
                
            # Cookies Analysis
            for cookie in response.cookies:
                if 'JSESSIONID' in cookie.name:
                    tech_stack['Language'] = "Java"
                if 'PHPSESSID' in cookie.name:
                    tech_stack['Language'] = "PHP"
                if 'csrftoken' in cookie.name and 'django' not in tech_stack.get('Framework', '').lower():
                    tech_stack['Framework'] = "Django (Likely)"

            # 2. HTML Analysis
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Meta Generators
            generator = soup.find('meta', attrs={'name': 'generator'})
            if generator and generator.get('content'):
                tech_stack['CMS/Generator'] = generator['content']
                
            # Script Sources (Simple heuristics)
            scripts = [s.get('src', '') for s in soup.find_all('script') if s.get('src')]
            for src in scripts:
                if 'wp-content' in src:
                    tech_stack['CMS'] = "WordPress"
                if 'jquery' in src:
                    tech_stack['Library'] = "jQuery"
                if 'bootstrap' in src:
                    tech_stack['UI'] = "Bootstrap"
                if '_next/static' in src:
                    tech_stack['Framework'] = "Next.js"
                    
            return tech_stack
            
        except Exception as e:
            print(f"[!] Detection Error: {e}")
            return {"error": str(e)}
