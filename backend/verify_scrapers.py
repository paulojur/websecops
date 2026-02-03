import sys
import os

# Ensure we can import from app
sys.path.append(os.path.join(os.getcwd()))

from app.scrapers.feed import CyberPressScraper, TheHackerNewsScraper, OwaspScraper
from app.scrapers.nvd import NVDScraper

def main():
    print("=== STARTING SCRAPER VERIFICATION ===")
    
    scrapers = [
        CyberPressScraper(),
        TheHackerNewsScraper(),
        OwaspScraper(),
        NVDScraper() 
    ]

    for scraper in scrapers:
        print(f"\n--- Testing {scraper.source_name} ---")
        data = scraper.run()
        if data:
            print(f"First item: {data[0]}")
        else:
            print("No data returned.")

    print("\n=== VERIFICATION COMPLETE ===")

if __name__ == "__main__":
    main()
