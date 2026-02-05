from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Dict, Any
from pydantic import BaseModel
from datetime import datetime

from ...core.database import get_db
from ...models.models import Target, Vulnerability
from ...services.tech_detector import TechDetector
from sqlalchemy import or_

router = APIRouter()
detector = TechDetector()

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
    Search DB for CVEs related to detected technologies.
    """
    if not technologies:
        return 0
    
    keywords = []
    # Extract keywords from tech stack values
    for key, value in technologies.items():
        # Generate multiple keywords for better matching
        # 1. Full value (e.g. "Apache/2.4.49")
        keywords.append(value)
        
        # 2. Base product (e.g. "Apache")
        base_val = value.split('/')[0].split(' ')[0]
        if len(base_val) > 3 and base_val != value:
            keywords.append(base_val)
            
    if not keywords:
        return 0
        
    # Build OR query
    query_filters = [Vulnerability.description.ilike(f"%{k}%") for k in keywords]
    count = db.query(Vulnerability).filter(or_(*query_filters)).count()
    return count

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
@router.get("/{target_id}/correlations", response_model=List[dict])
def get_target_correlations(target_id: int, db: Session = Depends(get_db)):
    """
    Get list of CVEs correlated to the target's tech stack.
    """
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    technologies = target.technologies
    if not technologies:
        return []
        
    keywords = []
    for key, value in technologies.items():
        # Generate multiple keywords for better matching
        # 1. Full value
        keywords.append(value)
        
        # 2. Base product
        clean_val = value.split('/')[0].split(' ')[0]
        if len(clean_val) > 3 and clean_val != value:
            keywords.append(clean_val)
            
    if not keywords:
        return []
        
    query_filters = [Vulnerability.description.ilike(f"%{k}%") for k in keywords]
    vulns = db.query(Vulnerability).filter(or_(*query_filters)).order_by(Vulnerability.published_date.desc()).limit(50).all()
    
    return [
        {
            "id": v.cve_id,
            "title": v.title,
            "description": v.description,
            "severity": v.severity,
            "published": v.published_date,
            "matched_keyword": " | ".join([k for k in keywords if k.lower() in v.description.lower()])
        }
        for v in vulns
    ]

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
