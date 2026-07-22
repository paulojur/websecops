from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.endpoints import vulnerabilities, intelligence, zap, targets, nuclei
from app.core.database import engine, Base
from app.models import models
from app.core.logging_config import setup_logging

logger = setup_logging()

app = FastAPI(title="CyberRisk Intel API", version="0.1.0", redirect_slashes=False)

import threading

@app.on_event("startup")
def startup_event():
    logger.info("Starting up CyberRisk Intel API...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created.")

    # Auto-sync on startup if database is empty
    def _initial_sync():
        from app.core.database import SessionLocal
        from app.models.models import Vulnerability, Intelligence
        db = SessionLocal()
        try:
            vuln_count = db.query(Vulnerability).count()
            intel_count = db.query(Intelligence).count()

            if vuln_count == 0:
                logger.info("Vulnerability table is empty. Triggering automatic initial NVD sync...")
                from app.scrapers.nvd import NVDScraper
                from app.api.endpoints.vulnerabilities import _parse_iso_date
                scraper = NVDScraper()
                data = scraper.fetch_data()
                for item in data:
                    vuln = Vulnerability(
                        cve_id=item['id'],
                        title=item['title'],
                        description=item['description'],
                        severity=item['severity'],
                        score=item['score'],
                        published_date=_parse_iso_date(item.get('published_date')),
                        last_modified_date=_parse_iso_date(item.get('modified_date')),
                        source=item['source']
                    )
                    db.add(vuln)
                db.commit()
                logger.info("Automatic NVD sync completed.")

            if intel_count == 0:
                logger.info("Intelligence table is empty. Triggering automatic initial feed sync...")
                from app.scrapers.feed import TheHackerNewsScraper, OwaspScraper, CisaScraper, GoogleSecScraper
                scrapers = [TheHackerNewsScraper(), OwaspScraper(), CisaScraper(), GoogleSecScraper()]
                for scraper in scrapers:
                    try:
                        data = scraper.fetch_data()
                        for item in data:
                            exists = db.query(Intelligence).filter(Intelligence.link == item['link']).first()
                            if not exists:
                                intel = Intelligence(
                                    source=item['source'],
                                    title=item['title'],
                                    link=item['link'],
                                    summary=item['summary'],
                                    published_date=item['published_date']
                                )
                                db.add(intel)
                    except Exception as fe:
                        logger.warning(f"Error fetching feed with {scraper}: {fe}")
                db.commit()
                logger.info("Automatic feed sync completed.")
        except Exception as e:
            logger.error(f"Error during initial startup sync: {e}")
            db.rollback()
        finally:
            db.close()

    threading.Thread(target=_initial_sync, daemon=True).start()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(vulnerabilities.router, prefix="/api/v1/vulnerabilities", tags=["vulnerabilities"])
app.include_router(intelligence.router, prefix="/api/v1/intelligence", tags=["intelligence"])
app.include_router(zap.router, prefix="/api/v1/zap", tags=["zap"])
app.include_router(targets.router, prefix="/api/v1/targets", tags=["targets"])
app.include_router(nuclei.router, prefix="/api/v1/nuclei", tags=["nuclei"])

@app.get("/")
def read_root():
    return {"status": "online", "system": "CyberRisk Intelligence Platform"}

@app.get("/health")
def health_check():
    return {"status": "healthy"}
