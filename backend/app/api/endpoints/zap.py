from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from sqlalchemy.orm import Session
from sqlalchemy import or_
from app.core.database import get_db
from app.models.models import Target, Vulnerability
from typing import Dict, Any, Optional
from app.services.zap_scanner import ZapScanner
from app.services.remediation_engine import RemediationEngine
from app.core.security import verify_api_key

router = APIRouter()
scanner = ZapScanner()
remediation_engine = RemediationEngine()

@router.post("/spider")
def start_spider_scan(target_url: str, api_key: str = Depends(verify_api_key)):
    """
    Starts a Passive Spider Scan (Crawling & Passive Analysis).
    Safe for most targets.
    """
    result = scanner.start_spider(target_url)
    return result

@router.post("/active")
def start_active_scan(target_url: str, api_key: str = Depends(verify_api_key)):
    """
    Starts an Active Vulnerability Scan (Attacking).
    Use with caution.
    """
    result = scanner.start_active_scan(target_url)
    return result

@router.get("/status/{scan_type}/{scan_id}")
def check_scan_status(scan_type: str, scan_id: str):
    """
    Get progress (0-100) of a scan.
    scan_type: 'spider' or 'active'
    """
    if scan_type not in ['spider', 'active']:
        raise HTTPException(status_code=400, detail="Invalid scan type")
        
    status_info = scanner.get_progress(scan_id, "spider" if scan_type == "spider" else "ascan")
    progress = status_info["progress"]
    
    return {
        "status": "scanning" if progress < 100 else "completed", 
        "progress": progress,
        "details": status_info["details"]
    }

@router.get("/results")
def get_scan_results(target_url: str, db: Session = Depends(get_db)):
    """
    Retrieves scan results/alerts and coverage report for a given target.
    Merges static CVEs (from tech detection) with dynamic ZAP alerts.
    """
    # 1. Get ZAP Alerts
    alerts_data = scanner.get_alerts(target_url)
    alerts_list = alerts_data.get("alerts", [])
    print(f"[DEBUG] ZAP Returned {len(alerts_list)} alerts for {target_url}")

    # 2. Get Static CVEs from DB
    try:
        target = db.query(Target).filter(Target.url == target_url).first()
        if target and target.technologies:
            filters = []
            for tech_name, tech_info in target.technologies.items():
                if not tech_name:
                    continue
                version = tech_info.get("version")
                if version:
                    exact_match = f"{tech_name} {version}"
                    filters.append(Vulnerability.description.ilike(f"%{exact_match}%"))
                    clean_version = version.split('-')[0].split('.')[0]
                    if clean_version and clean_version != version:
                        filters.append(Vulnerability.description.ilike(f"%{tech_name} {clean_version}%"))
                else:
                    filters.append(Vulnerability.title.ilike(f"%{tech_name}%"))
            
            if filters:
                # Need to import or_ if it's not already (it is imported at top)
                vulns = db.query(Vulnerability).filter(or_(*filters)).limit(100).all()
                
                # Map CVEs to ZAP Alert format
                for v in vulns:
                    alerts_list.append({
                        "alert": f"{v.cve_id}: {v.title}",
                        "risk": v.severity.capitalize() if v.severity else "Medium",
                        "confidence": "High", # Static detection is usually high confidence
                        "description": v.description,
                        "solution": "Update the affected component to a patched version.",
                        "url": target_url,
                        "cweid": "0", # Could map if we had CWE in DB
                        "wascid": "0",
                        "sourceid": "static_analysis"
                    })
    except Exception as e:
        print(f"Error accessing database during results merge: {e}")
        # Proceed with just ZAP alerts

    for alert in alerts_list:
        alert["remediations"] = remediation_engine.for_alert(alert)
    
    # Update alerts in the response wrapper
    alerts_data["alerts"] = alerts_list
    alerts_data["hardening"] = remediation_engine.baseline(target.technologies if "target" in locals() and target else {})
    alerts_data["triage"] = remediation_engine.summarize_alerts(alerts_list)

    # 3. Generate Report (Coverage)
    report = scanner.get_full_report(target_url, alerts_list)
    return {**alerts_data, **report}

from pydantic import BaseModel
from typing import List, Optional

class SaveHistoryRequest(BaseModel):
    target_url: str
    scan_type: str
    alerts: Optional[List[dict]] = None

from app.models.models import ScanHistory
import datetime

@router.post("/save-history")
def save_scan_history(req: SaveHistoryRequest, db: Session = Depends(get_db), api_key: str = Depends(verify_api_key)):
    """
    Fetches the current results for a target and saves them into the ScanHistory table.
    Filters to only keep High and Medium severity to save space.
    """
    target = db.query(Target).filter(Target.url == req.target_url).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found in DB")
        
    alerts = req.alerts
    if alerts is None:
        try:
            results = get_scan_results(req.target_url, db)
            alerts = results.get("alerts", [])
        except Exception as e:
            print(f"Error fetching results from ZAP: {e}")
            alerts = []
    
    # Filter for Critical, High, Medium
    important_alerts = [a for a in alerts if a.get("risk", "").upper() in ["CRITICAL", "HIGH", "MEDIUM"]]
    
    # Count them
    summary = {
        "CRITICAL": sum(1 for a in important_alerts if a.get("risk", "").upper() == "CRITICAL"),
        "HIGH": sum(1 for a in important_alerts if a.get("risk", "").upper() == "HIGH"),
        "MEDIUM": sum(1 for a in important_alerts if a.get("risk", "").upper() == "MEDIUM")
    }
    
    history_entry = ScanHistory(
        target_id=target.id,
        scan_type=req.scan_type,
        created_at=datetime.datetime.utcnow(),
        summary=summary,
        critical_findings=important_alerts
    )
    
    db.add(history_entry)
    db.commit()
    db.refresh(history_entry)
    
    return {"status": "success", "history_id": history_entry.id}

