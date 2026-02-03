from sqlalchemy.orm import Session
from app.models.models import Vulnerability, Intelligence
from app.scrapers.feed import CyberPressScraper, TheHackerNewsScraper, OwaspScraper
from app.scrapers.nvd import NVDScraper
from app.core.database import SessionLocal
from typing import List, Dict, Any
from datetime import datetime

class DataPipeline:
    def __init__(self, db: Session):
        self.db = db

    def save_vulnerabilities(self, data: List[Dict[str, Any]]):
        count = 0
        for item in data:
            # Check if exists
            exists = self.db.query(Vulnerability).filter(Vulnerability.cve_id == item['id']).first()
            if not exists:
                vuln = Vulnerability(
                    cve_id=item['id'],
                    title=item['title'],
                    description=item['description'],
                    severity=item['severity'],
                    score=item['score'],
                    published_date=datetime.fromisoformat(item['published_date'].replace('Z', '+00:00')) if item['published_date'] else None,
                    last_modified_date=datetime.fromisoformat(item['modified_date'].replace('Z', '+00:00')) if item['modified_date'] else None,
                    source=item['source']
                )
                self.db.add(vuln)
                count += 1
            else:
                # Update? For now skip
                pass
        self.db.commit()
        print(f"[+] Saved {count} new vulnerabilities.")

    def save_intelligence(self, data: List[Dict[str, Any]]):
        count = 0
        for item in data:
            # Check if exists
            exists = self.db.query(Intelligence).filter(Intelligence.link == item['link']).first()
            if not exists:
                intel = Intelligence(
                    source=item['source'],
                    title=item['title'],
                    link=item['link'],
                    summary=item['summary'],
                    published_date=datetime.fromisoformat(item['published_date']) if 'published_date' in item else datetime.now()
                )
                self.db.add(intel)
                count += 1
        self.db.commit()
        print(f"[+] Saved {count} new intelligence items.")

    def run_all(self):
        print("=== RUNNING DATA PIPELINE ===")
        
        # 1. News
        news_scrapers = [CyberPressScraper(), TheHackerNewsScraper(), OwaspScraper()]
        for scraper in news_scrapers:
            data = scraper.run()
            self.save_intelligence(data)

        # 2. NVD
        nvd = NVDScraper()
        data = nvd.run()
        self.save_vulnerabilities(data)
        
        print("=== PIPELINE FINISHED ===")

if __name__ == "__main__":
    db = SessionLocal()
    pipeline = DataPipeline(db)
    pipeline.run_all()
    db.close()
