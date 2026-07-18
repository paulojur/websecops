from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Dict, Any
from pydantic import BaseModel
from datetime import datetime
from urllib.parse import urlparse, urlunparse
from sqlalchemy import or_

from ...core.database import get_db
from ...core.config import settings
from ...models.models import Target, Vulnerability
from ...services.tech_detector import TechDetector
from ...services.cve_searcher import CVESearcher
from ...services.asm_recon import ASMRecon
from ...services.remediation_engine import RemediationEngine

router = APIRouter()
detector = TechDetector()
cve_searcher = CVESearcher(api_key=settings.NVD_API_KEY)
asm = ASMRecon()
remediation_engine = RemediationEngine()

class TargetCreate(BaseModel):
    url: str

class TargetResponse(BaseModel):
    id: int
    url: str
    technologies: Dict[str, Any]
    subdomains: List[str] = []
    vuln_status: str
    last_scan: datetime | None
    potential_vulns: int = 0

    class Config:
        from_attributes = True


def normalize_url(raw_url: str) -> str:
    """Ensure the target URL has a scheme and valid host."""
    value = (raw_url or "").strip()
    if not value:
        raise HTTPException(status_code=400, detail="URL is required")

    if "://" not in value:
        value = f"https://{value}"

    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        raise HTTPException(status_code=400, detail="Invalid URL")

    return urlunparse(parsed)


def calculate_risk(db: Session, technologies: Dict[str, Any]) -> int:
    """
    Search for CVEs related to detected technologies using exact versions.
    Counts candidate matches in the local vulnerability database.
    """
    if not technologies:
        return 0

    filters = []
    for tech_name, tech_info in technologies.items():
        if not tech_name:
            continue
            
        # Skip generic / non-correlatable entries (e.g. "HTML - Markup Language")
        category = (tech_info.get("category") or "").strip()
        if category in {"Markup Language"} or tech_name in {"HTML", "HTML5"}:
            continue

        # The new format is {"WordPress": {"version": "6.4.2", "category": "CMS"}}
        version = tech_info.get("version")
        
        # We search the exact phrase "WordPress 6.4" or "WordPress" if no version
        if version:
            # Try to build a more precise CPE-like string or just Name + Version
            exact_match = f"{tech_name} {version}"
            filters.append(Vulnerability.description.ilike(f"%{exact_match}%"))
            # Also fallback to base name if version is very long/complex
            clean_version = version.split('-')[0].split('.')[0]
            if clean_version and clean_version != version:
                 filters.append(Vulnerability.description.ilike(f"%{tech_name} {clean_version}%"))
        else:
            # Only if we really don't have a version, we fallback to just the name,
            # but this increases false positives.
            filters.append(Vulnerability.title.ilike(f"%{tech_name}%"))

    if not filters:
        return 0

    try:
        # Use or_ to count any matches for any of the detected technologies
        return db.query(Vulnerability).filter(or_(*filters)).count()
    except Exception as e:
        print(f"Error calculating risk: {e}")
        return 0


def build_correlation_explanation(vuln: Dict[str, Any]) -> Dict[str, str]:
    """Create a small, deterministic explanation for a CVE correlation."""
    keyword = str(vuln.get("matched_keyword") or "").strip()

    if keyword:
        if any(char.isdigit() for char in keyword):
            return {
                "correlation_reason": f"Correlacao por tecnologia e versao detectadas em '{keyword}'.",
                "confidence": "HIGH",
                "confidence_reason": "A busca encontrou nome + versao, o que reduz o ruido da correlacao local.",
            }

        return {
            "correlation_reason": f"Correlacao por nome da tecnologia em '{keyword}'.",
            "confidence": "LOW",
            "confidence_reason": "Nao ha versao confirmada; trate este item como hipotese ate validar o inventario real.",
        }

    score = vuln.get("score")
    if score:
        return {
            "correlation_reason": f"Correlacao baseada em CVSS {score} e nos sinais de tecnologia do alvo.",
            "confidence": "LOW",
            "confidence_reason": "Nao foi possivel extrair uma chave de correlacao mais especifica.",
        }

    return {
        "correlation_reason": "Associado com base nas tecnologias detectadas para o alvo.",
        "confidence": "LOW",
        "confidence_reason": "Nao foi possivel derivar uma correspondencia explicita entre tecnologia e CVE.",
    }

@router.post("/scan", response_model=TargetResponse)
def add_and_scan_target(target_in: TargetCreate, db: Session = Depends(get_db)):
    """
    Scans a new target URL (Passive) and saves/updates it in the database.
    Falls back gracefully when Wappalyzer or subdomain discovery fails.
    """
    normalized_url = normalize_url(target_in.url)

    # 1. Detect Technologies
    tech_stack = detector.detect(normalized_url)
    if "error" in tech_stack:
        print(f"[!] Tech detection failed for {normalized_url}: {tech_stack['error']}")
        tech_stack = {}

    # 2. Subdomain Discovery (ASM)
    try:
        discovered_subdomains = asm.discover_subdomains(normalized_url)
    except Exception as exc:
        print(f"[!] Subdomain discovery failed for {normalized_url}: {exc}")
        discovered_subdomains = []

    # 3. Update or Create in DB
    risk_count = calculate_risk(db, tech_stack)
    status = "VULNERABLE" if risk_count > 0 else "SECURE"

    existing = db.query(Target).filter(Target.url == normalized_url).first()

    if existing:
        existing.technologies = tech_stack
        existing.subdomains = discovered_subdomains
        existing.last_scan = datetime.utcnow()
        existing.vuln_status = status
        db.commit()
        db.refresh(existing)
        existing.potential_vulns = risk_count
        return existing
    else:
        new_target = Target(
            url=normalized_url,
            technologies=tech_stack,
            subdomains=discovered_subdomains,
            vuln_status=status,
            last_scan=datetime.utcnow()
        )
        db.add(new_target)
        db.commit()
        db.refresh(new_target)
        new_target.potential_vulns = risk_count
        return new_target

@router.post("/analyze")
def analyze_target(target_in: TargetCreate, db: Session = Depends(get_db)):
    """
    Stateless endpoint for Demo Mode.
    Scans the target, detects technologies, and correlates CVEs without saving to the DB.
    """
    normalized_url = normalize_url(target_in.url)

    # 1. Detect Technologies
    tech_stack = detector.detect(normalized_url)
    if "error" in tech_stack:
        tech_stack = {}

    risk_count = calculate_risk(db, tech_stack)
    status = "VULNERABLE" if risk_count > 0 else "SECURE"
    
    import random
    mock_id = random.randint(10000, 99999)
    
    target_data = {
        "id": mock_id,
        "url": normalized_url,
        "technologies": tech_stack,
        "subdomains": [],
        "vuln_status": status,
        "last_scan": datetime.utcnow().isoformat(),
        "potential_vulns": risk_count
    }

    # 2. Correlate CVEs
    correlations = []
    summary = ""
    hardening = {}
    
    if tech_stack:
        keywords = []
        for tech_name, tech_info in tech_stack.items():
            version = tech_info.get("version")
            if version:
                 keywords.append(f"{tech_name} {version}")
                 keywords.append(tech_name)
            else:
                 keywords.append(tech_name)
                
        if keywords:
            vulns = cve_searcher.search(keywords)
            enriched_vulns = []
            for vuln in vulns:
                cve_id = vuln.get("cve_id") or vuln.get("id")
                explanation = build_correlation_explanation(vuln)
                enriched_vulns.append({
                    **vuln,
                    "cve_id": cve_id,
                    **explanation,
                    "remediation": remediation_engine.for_cve(vuln),
                })
            
            prioritized_vulns = remediation_engine.prioritize(enriched_vulns)
            correlations = prioritized_vulns
            summary = remediation_engine.summarize_target(prioritized_vulns)
            hardening = remediation_engine.baseline(tech_stack)

    # Add correlations inside target_data so frontend can easily store it together
    target_data["correlations"] = correlations

    return {
        "target": target_data,
        "correlations": correlations,
        "summary": summary,
        "hardening": hardening,
    }


@router.get("", response_model=List[TargetResponse])
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
    for tech_name, tech_info in technologies.items():
        version = tech_info.get("version")
        if version:
             keywords.append(f"{tech_name} {version}")
             # Also add base name in case exact version yields nothing
             keywords.append(tech_name)
        else:
             keywords.append(tech_name)
            
    if not keywords:
        return {"target": target, "correlations": []}
        
    # Real-time search
    vulns = cve_searcher.search(keywords)
    enriched_vulns = []
    for vuln in vulns:
        cve_id = vuln.get("cve_id") or vuln.get("id")
        explanation = build_correlation_explanation(vuln)
        enriched_vulns.append({
            **vuln,
            "cve_id": cve_id,
            **explanation,
            "remediation": remediation_engine.for_cve(vuln),
        })
    
    prioritized_vulns = remediation_engine.prioritize(enriched_vulns)

    return {
        "target": target,
        "correlations": prioritized_vulns,
        "summary": remediation_engine.summarize_target(prioritized_vulns),
        "hardening": remediation_engine.baseline(technologies),
    }

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

from app.models.models import ScanHistory

@router.get("/{target_id}/history")
def get_target_scan_history(target_id: int, db: Session = Depends(get_db)):
    """
    Get the ZAP scan history for a specific target.
    """
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    history = db.query(ScanHistory).filter(ScanHistory.target_id == target_id).order_by(ScanHistory.created_at.desc()).all()
    return history
