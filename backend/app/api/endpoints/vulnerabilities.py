from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime
from ...core.database import get_db
from ...models.models import Vulnerability

router = APIRouter()

def _parse_iso_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00'))
    except Exception:
        return None

@router.get("/", response_model=List[dict])
def read_vulnerabilities(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """
    Get list of vulnerabilities.
    """
    vulns = db.query(Vulnerability).order_by(Vulnerability.published_date.desc()).offset(skip).limit(limit).all()
    return [
        {
            "id": v.cve_id,
            "title": v.title,
            "description": v.description,
            "severity": v.severity,
            "score": v.score,
            "published": v.published_date,
            "source": v.source
        }
        for v in vulns
    ]

@router.get("/stats")
def read_stats(db: Session = Depends(get_db)):
    """
    Get high-level statistics.
    """
    total = db.query(Vulnerability).count()
    critical = db.query(Vulnerability).filter(Vulnerability.severity == "CRITICAL").count()
    high = db.query(Vulnerability).filter(Vulnerability.severity == "HIGH").count()
    return {
        "total_tracked": total,
        "critical_count": critical,
        "high_count": high
    }

@router.post("/sync")
def sync_vulnerabilities(db: Session = Depends(get_db)):
    """
    Trigger manual NVD synchronization.
    """
    from ...scrapers.nvd import NVDScraper
    
    scraper = NVDScraper()
    try:
        data = scraper.fetch_data()
        count = 0
        for item in data:
            exists = db.query(Vulnerability).filter(Vulnerability.cve_id == item['id']).first()
            if not exists:
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
                count += 1
            else:
                updated = False
                if exists.title != item['title']:
                    exists.title = item['title']
                    updated = True
                if exists.description != item['description']:
                    exists.description = item['description']
                    updated = True
                if exists.severity != item['severity']:
                    exists.severity = item['severity']
                    updated = True
                if exists.score != item['score']:
                    exists.score = item['score']
                    updated = True
                pub_date = _parse_iso_date(item.get('published_date'))
                if pub_date and exists.published_date != pub_date:
                    exists.published_date = pub_date
                    updated = True
                mod_date = _parse_iso_date(item.get('modified_date'))
                if mod_date and exists.last_modified_date != mod_date:
                    exists.last_modified_date = mod_date
                    updated = True
                if updated:
                    count += 1
        
        db.commit()
        return {"status": "success", "added": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
