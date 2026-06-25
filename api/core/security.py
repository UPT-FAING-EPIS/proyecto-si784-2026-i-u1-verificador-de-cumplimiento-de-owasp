"""
api/core/security.py
Dependency de FastAPI para autenticación por API Key.
Si REQUIRE_AUTH=false (default), permite acceso sin token para facilitar pruebas.
Cuando está activo, valida el token contra scan_store (mismo store que la app web).
"""
from fastapi import Header, HTTPException, status
from typing import Optional

from api.core.config import get_api_settings
from app.store import scan_store


async def get_current_user(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> str:
    """
    Dependency que verifica el API Key.
    Devuelve el nombre de usuario si es válido, o 'anonymous' si auth está desactivada.
    """
    settings = get_api_settings()

    if not settings.require_auth:
        # Modo sin auth: permite llamadas sin token, pero si se envía uno lo valida
        if x_api_key:
            result = scan_store.validate_token(x_api_key)
            return result["user"] if result else "anonymous"
        return "anonymous"

    # Modo con auth requerida
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key requerida. Incluye el header 'X-API-Key: <tu-token>'",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    result = scan_store.validate_token(x_api_key)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key inválida o expirada",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    return result["user"]


# Dependency opcional — no lanza error si no hay token
async def get_optional_user(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> Optional[str]:
    """Dependency que devuelve el usuario si hay token válido, o None si no hay token."""
    if not x_api_key:
        return None
    result = scan_store.validate_token(x_api_key)
    return result["user"] if result else None
