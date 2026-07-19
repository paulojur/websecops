import os
from fastapi import Security, HTTPException, status
from fastapi.security.api_key import APIKeyHeader

# Nome do header que será enviado pelo frontend
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

# Puxa a chave do .env, com um default seguro caso não seja informada.
# O usuário deve adicionar ADMIN_API_KEY=sua_senha_aqui no .env
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "M3uP0rtf0li0S3cur3")

async def verify_api_key(api_key_header: str = Security(api_key_header)):
    if api_key_header == ADMIN_API_KEY:
        return api_key_header
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API Key",
    )
