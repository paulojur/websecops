from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List
from ...core.database import get_db
from ...models.models import Intelligence

router = APIRouter()

@router.get("", response_model=List[dict])
@router.get("/", response_model=List[dict])
def read_intelligence(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    """
    Get latest intelligence feed items.
    """
    items = db.query(Intelligence).order_by(Intelligence.published_date.desc()).offset(skip).limit(limit).all()
    return [
        {
            "id": i.id,
            "source": i.source,
            "title": i.title,
            "link": i.link,
            "summary": i.summary,
            "published": i.published_date
        }
        for i in items
    ]
@router.post("/sync")
def sync_intelligence(db: Session = Depends(get_db)):
    """
    Trigger manual Intelligence feed synchronization.
    """
    from ...scrapers.feed import TheHackerNewsScraper, OwaspScraper, CisaScraper, GoogleSecScraper
    
    scrapers = [TheHackerNewsScraper(), OwaspScraper(), CisaScraper(), GoogleSecScraper()]
    count = 0
    
    try:
        for scraper in scrapers:
            data = scraper.fetch_data()
            for item in data:
                # Check duplication by link
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
                    count += 1
        
        db.commit()
        return {"status": "success", "added": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
