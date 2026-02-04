import feedparser
from typing import List, Dict, Any
from .base import BaseScraper
from datetime import datetime
import time

class RSSScraper(BaseScraper):
    def __init__(self, source_name: str, rss_url: str):
        super().__init__(source_name)
        self.rss_url = rss_url

    def fetch_data(self) -> List[Dict[str, Any]]:
        # Add User-Agent to avoid blocking
        feed = feedparser.parse(self.rss_url, agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        return self.parse_data(feed.entries)

    def parse_data(self, entries: Any) -> List[Dict[str, Any]]:
        normalized_items = []
        for entry in entries:
            try:
                # Robust date parsing
                published = datetime.now().isoformat()
                if hasattr(entry, 'published_parsed') and entry.published_parsed:
                     published = datetime(*entry.published_parsed[:6]).isoformat()
                elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
                     published = datetime(*entry.updated_parsed[:6]).isoformat()

                item = {
                    "source": self.source_name,
                    "title": entry.get("title", "No Title"),
                    "link": entry.get("link", ""),
                    "published_date": published,
                    "summary": entry.get("summary", "")[:500], # Limit summary size
                    "type": "news"
                }
                normalized_items.append(item)
            except Exception as e:
                print(f"Error parsing item from {self.source_name}: {e}")
                continue
        return normalized_items

# Updated Scrapers with working URLs
class CyberPressScraper(RSSScraper):
    def __init__(self):
        super().__init__("Cyber Press", "https://cyberpress.org/feed/")

class TheHackerNewsScraper(RSSScraper):
    def __init__(self):
        # Alternative FeedBurner often has issues, switching to main if possible or keeping robust
        super().__init__("The Hacker News", "https://feeds.feedburner.com/TheHackersNews")

class OwaspScraper(RSSScraper):
    def __init__(self):
        super().__init__("OWASP", "https://owasp.org/feed.xml")

class CisaScraper(RSSScraper):
    def __init__(self):
        super().__init__("CISA Alerts", "https://www.cisa.gov/cybersecurity-alerts/us-cert.xml")

class GoogleSecScraper(RSSScraper):
    def __init__(self):
        super().__init__("Google Security", "https://feeds.feedburner.com/GoogleOnlineSecurityBlog")
