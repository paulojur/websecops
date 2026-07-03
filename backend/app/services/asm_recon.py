import requests
import json
from typing import List
from urllib.parse import urlparse

class ASMRecon:
    """
    Attack Surface Management - Reconnaissance Module.
    Responsible for discovering subdomains and extending the attack surface.
    """
    
    def __init__(self):
        self.crt_sh_url = "https://crt.sh/"

    def extract_domain(self, url: str) -> str:
        """Extracts the root domain from a given URL."""
        if not url.startswith("http"):
            url = "http://" + url
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.split(":")[0]  # Remove port if present
        
        # Simple domain extraction (works for basic cases like example.com)
        parts = domain.split('.')
        if len(parts) > 2:
            # Handle co.uk etc. naively for now, or just return the last 2 parts
            if parts[-2] in ['co', 'com', 'org', 'net', 'gov', 'edu'] and len(parts) >= 3:
                return ".".join(parts[-3:])
            return ".".join(parts[-2:])
        return domain

    def discover_subdomains(self, url: str) -> List[str]:
        """
        Uses crt.sh (Certificate Transparency Logs) to passively 
        discover subdomains for a given URL.
        """
        domain = self.extract_domain(url)
        if not domain:
            return []
            
        print(f"[*] Starting Subdomain Discovery (crt.sh) for {domain}...")
        subdomains = set()
        
        try:
            params = {
                "q": f"%.{domain}",
                "output": "json"
            }
            # Add headers to act as a normal browser to avoid simple bot blocks
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
            response = requests.get(self.crt_sh_url, params=params, headers=headers, timeout=20)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    # crt.sh can return multiple domains separated by newlines
                    for name in name_value.split('\n'):
                        clean_name = name.strip().lower()
                        if clean_name and not clean_name.startswith('*'):
                            subdomains.add(clean_name)
                            
                print(f"[+] Found {len(subdomains)} subdomains for {domain}.")
                return sorted(list(subdomains))
            else:
                print(f"[!] crt.sh returned status code {response.status_code}")
        except Exception as e:
            print(f"[!] Error discovering subdomains via crt.sh: {e}")
            
        return []

if __name__ == "__main__":
    recon = ASMRecon()
    subs = recon.discover_subdomains("https://example.com")
    print(subs)
