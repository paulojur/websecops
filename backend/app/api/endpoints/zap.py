from fastapi import APIRouter, HTTPException
from typing import Dict, Any
from app.services.zap_scanner import ZapScanner

router = APIRouter()
scanner = ZapScanner()

@router.post("/scan")
def trigger_scan(target_url: str):
    """
    Triggers an OWASP ZAP scan on the specified target URL.
    """
    result = scanner.scan_target(target_url)
    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result.get("message"))
    return result

@router.get("/results")
def get_scan_results(target_url: str):
    """
    Retrieves scan results/alerts for a given target.
    """
    return scanner.get_results(target_url)
