from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from sqlalchemy.orm import Session
from sqlalchemy import or_
from app.core.database import get_db
from app.models.models import Target, Vulnerability
from typing import Dict, Any, Optional
from app.services.zap_scanner import ZapScanner
from app.services.remediation_engine import RemediationEngine

router = APIRouter()
scanner = ZapScanner()
remediation_engine = RemediationEngine()

@router.post("/spider")
def start_spider_scan(target_url: str):
    """
    Starts a Passive Spider Scan (Crawling & Passive Analysis).
    Safe for most targets.
    """
    result = scanner.start_spider(target_url)
    return result

@router.post("/active")
def start_active_scan(target_url: str):
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

    # 3. Generate Report (Coverage)
    report = scanner.get_full_report(target_url, alerts_list)
    return {**alerts_data, **report}
