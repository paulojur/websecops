from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Dict, Any
from pydantic import BaseModel
from datetime import datetime

from ...core.database import get_db
from ...core.config import settings
from ...models.models import Target, Vulnerability
from ...services.tech_detector import TechDetector
from ...services.cve_searcher import CVESearcher
from sqlalchemy import or_

router = APIRouter()
detector = TechDetector()
cve_searcher = CVESearcher(api_key=settings.NVD_API_KEY)

class TargetCreate(BaseModel):
    url: str

class TargetResponse(BaseModel):
    id: int
    url: str
    technologies: Dict[str, Any]
    vuln_status: str
    last_scan: datetime | None
    potential_vulns: int = 0

    class Config:
        from_attributes = True

def calculate_risk(db: Session, technologies: Dict[str, Any]) -> int:
    """
    Search for CVEs related to detected technologies.
    Now just returns 0 during initial scan to keep it fast. 
    The real correlations are fetched on demand.
    """
    return 0

@router.post("/scan", response_model=TargetResponse)
def add_and_scan_target(target_in: TargetCreate, db: Session = Depends(get_db)):
    """
    Scans a new target URL (Passive) and saves/updates it in the database.
    """
    # 1. Detect Technologies
    tech_stack = detector.detect(target_in.url)
    if "error" in tech_stack:
        raise HTTPException(status_code=400, detail=tech_stack["error"])

    # 2. Update or Create in DB
    risk_count = calculate_risk(db, tech_stack)
    status = "VULNERABLE" if risk_count > 0 else "SECURE"

    existing = db.query(Target).filter(Target.url == target_in.url).first()
    
    if existing:
        existing.technologies = tech_stack
        existing.last_scan = datetime.utcnow()
        existing.vuln_status = status
        db.commit()
        db.refresh(existing)
        # Inject dynamic field
        existing.potential_vulns = risk_count
        return existing
    else:
        new_target = Target(
            url=target_in.url,
            technologies=tech_stack,
            vuln_status=status,
            last_scan=datetime.utcnow()
        )
        db.add(new_target)
        db.commit()
        db.refresh(new_target)
        new_target.potential_vulns = risk_count
        return new_target

@router.get("/", response_model=List[TargetResponse])
def get_targets(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """
    List all tracked targets.
    """
    targets = db.query(Target).offset(skip).limit(limit).all()
    for t in targets:
        t.potential_vulns = calculate_risk(db, t.technologies)
    return targets
@router.get("/{target_id}/correlations")
def get_target_correlations(target_id: int, db: Session = Depends(get_db)):
    """
    Get list of CVEs correlated to the target's tech stack.
    Fetches real-time data from NVD API.
    """
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    technologies = target.technologies
    if not technologies:
        return {"target": target, "correlations": []}
        
    keywords = []
    for key, value in technologies.items():
        # Prefer full exact version, if not fallback to just base tool
        clean_val = value.split('/')[0].split(' ')[0]
        
        # We always add the full value to try to get exact version matches first
        keywords.append(value)
        
        if len(clean_val) > 3 and clean_val != value:
             keywords.append(clean_val)
            
    if not keywords:
        return {"target": target, "correlations": []}
        
    # Real-time search
    vulns = cve_searcher.search(keywords)
    
    return {"target": target, "correlations": vulns}

@router.delete("/{target_id}", status_code=204)
def delete_target(target_id: int, db: Session = Depends(get_db)):
    """
    Delete a target from the tracking list.
    """
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    db.delete(target)
    db.commit()
    return None
