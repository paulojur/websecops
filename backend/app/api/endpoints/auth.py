from fastapi import APIRouter, Depends
from app.core.security import verify_api_key

router = APIRouter()

@router.get("/verify")
def verify_admin_key(api_key: str = Depends(verify_api_key)):
    """
    Verifies if the provided API Key is valid.
    If valid, returns 200 OK.
    If invalid, verify_api_key will raise a 401 Unauthorized automatically.
    """
    return {"status": "success", "message": "API Key is valid"}
