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

async def verify_api_key(api_key_header: str = Security(api_key_header)):
    if api_key_header == ADMIN_API_KEY:
        return api_key_header
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API Key",
    )
