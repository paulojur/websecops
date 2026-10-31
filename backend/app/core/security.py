import os
from fastapi import Security, HTTPException, status
from fastapi.security.api_key import APIKeyHeader

# Nome do header que será enviado pelo frontend
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

import secrets
import logging

logger = logging.getLogger(__name__)

# Pulls the key from .env. If not provided, generates a secure random one at startup
# to prevent hardcoded credentials in the repository.
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY")
if not ADMIN_API_KEY:
    ADMIN_API_KEY = secrets.token_urlsafe(32)
    logger.warning("No ADMIN_API_KEY found in environment. A random secure key was generated for this session.")

def _is_admin_key(candidate: str | None) -> bool:
    """Constant-time comparison to avoid timing attacks."""
    if not candidate:
        return False
    return secrets.compare_digest(candidate.encode(), ADMIN_API_KEY.encode())

async def verify_api_key(api_key_header: str = Security(api_key_header)):
    if _is_admin_key(api_key_header):
        return api_key_header
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API Key",
    )

async def get_optional_api_key(api_key_header: str = Security(api_key_header)):
    """Returns the API key if valid, otherwise None (doesn't raise)."""
    if _is_admin_key(api_key_header):
        return api_key_header
    return None

WHITELISTED_DOMAINS = [
    "demo.testfire.net",
    "juice-shop.herokuapp.com",
    "scanme.nmap.org",
    "websecops.tech"
]

def enforce_security(target_url: str, api_key: str | None):
    """
    Enforces that either the user is an Admin (valid api_key) 
    OR the target_url belongs to the whitelist.
    Raises HTTPException if unauthorized.
    """
    if _is_admin_key(api_key):
        return True # Admin can scan anything
        
    from urllib.parse import urlparse
    
    # Try to parse the domain
    if not target_url.startswith("http"):
        target_url = "http://" + target_url
        
    parsed = urlparse(target_url)
    domain = parsed.netloc.lower()
    
    # Remove port if present
    if ":" in domain:
        domain = domain.split(":")[0]
        
    # Check whitelist (exact match or subdomain match)
    is_whitelisted = False
    for wl_domain in WHITELISTED_DOMAINS:
        if domain == wl_domain or domain.endswith("." + wl_domain):
            is_whitelisted = True
            break
            
    if not is_whitelisted:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Visitantes só podem auditar domínios pré-aprovados ({', '.join(WHITELISTED_DOMAINS)}). Use a Master Key para auditar qualquer domínio."
        )
    
    return True
