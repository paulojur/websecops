from fastapi import APIRouter, Depends, HTTPException
from typing import Any
from pydantic import BaseModel

from app.services.nuclei_scanner import NucleiScanner
from app.core.security import verify_api_key, get_optional_api_key, enforce_security

router = APIRouter()
scanner = NucleiScanner()

class ScanRequest(BaseModel):
    url: str

@router.post("/scan")
def start_scan(payload: ScanRequest, api_key: str = Depends(get_optional_api_key)) -> Any:
    """
    Start a Nuclei scan on the target URL.
    """
    if not payload.url:
        raise HTTPException(status_code=400, detail="URL is required")
        
    enforce_security(payload.url, api_key)
        
    result = scanner.start_scan(payload.url)
    return result

@router.get("/status")
def check_status(scanId: str, type: str = "nuclei") -> Any:
    """
    Check the status of a running scan.
    """
    if not scanId:
        raise HTTPException(status_code=400, detail="scanId is required")
        
    status = scanner.get_progress(scanId)
    return status

@router.get("/results")
def get_results(scanId: str) -> Any:
    """
    Retrieve results of a completed scan.
    """
    if not scanId:
        raise HTTPException(status_code=400, detail="scanId is required")
        
    results = scanner.get_results(scanId)
    return results
