from abc import ABC, abstractmethod
from typing import List, Dict, Any

class BaseScraper(ABC):
    def __init__(self, source_name: str):
        self.source_name = source_name

    @abstractmethod
    def fetch_data(self) -> List[Dict[str, Any]]:
        """
        Fetches data from the source.
        Returns a list of dictionaries representing the collected items.
        """
        pass

    @abstractmethod
    def parse_data(self, raw_data: Any) -> List[Dict[str, Any]]:
        """
        Parses raw data into a standardized format.
        """
        pass

    def run(self) -> List[Dict[str, Any]]:
        """
        Main execution method.
        """
        print(f"[*] Starting scraper for: {self.source_name}")
        try:
            data = self.fetch_data()
            print(f"[+] Successfully fetched {len(data)} items from {self.source_name}")
            return data
        except Exception as e:
            print(f"[!] Error scrapping {self.source_name}: {e}")
            return []
