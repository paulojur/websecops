import feedparser
from typing import List, Dict, Any
from .base import BaseScraper
from datetime import datetime

class RSSScraper(BaseScraper):
    def __init__(self, source_name: str, rss_url: str):
        super().__init__(source_name)
        self.rss_url = rss_url

    def fetch_data(self) -> List[Dict[str, Any]]:
        feed = feedparser.parse(self.rss_url)
        return self.parse_data(feed.entries)

    def parse_data(self, entries: Any) -> List[Dict[str, Any]]:
        normalized_items = []
        for entry in entries:
            item = {
                "source": self.source_name,
                "title": entry.get("title", "No Title"),
                "link": entry.get("link", ""),
                # Use parsed time struct if available, otherwise fallback
                "published_date": datetime(*entry.published_parsed[:6]).isoformat() if entry.get("published_parsed") else datetime.now().isoformat(),
                "summary": entry.get("summary", ""),
                "type": "news"
            }
            normalized_items.append(item)
        return normalized_items

# Pre-defined instances
class CyberPressScraper(RSSScraper):
    def __init__(self):
        super().__init__("Cyber Press", "https://cyberpress.org/feed/")

class TheHackerNewsScraper(RSSScraper):
    def __init__(self):
        super().__init__("The Hacker News", "https://feeds.feedburner.com/TheHackersNews")

class OwaspScraper(RSSScraper):
    def __init__(self):
        # OWASP blog feed
        super().__init__("OWASP", "https://owasp.org/feed.xml")
