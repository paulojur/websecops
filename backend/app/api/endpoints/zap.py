from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import Dict, Any, Optional
from app.services.zap_scanner import ZapScanner

router = APIRouter()
scanner = ZapScanner()

@router.post("/spider")
def start_spider_scan(target_url: str):
    """
    Starts a Passive Spider Scan (Crawling & Passive Analysis).
    Safe for most targets.
    """
    result = scanner.start_spider(target_url)
    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result.get("message"))
    return result

@router.post("/active")
def start_active_scan(target_url: str):
    """
    Starts an Active Vulnerability Scan (Attacking).
    Use with caution.
    """
    result = scanner.start_active_scan(target_url)
    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result.get("message"))
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
def get_scan_results(target_url: str):
    """
    Retrieves scan results/alerts and coverage report for a given target.
    """
    alerts_data = scanner.get_alerts(target_url)
    alerts_list = alerts_data.get("alerts", [])
    report = scanner.get_full_report(target_url, alerts_list)
    return {**alerts_data, **report}
