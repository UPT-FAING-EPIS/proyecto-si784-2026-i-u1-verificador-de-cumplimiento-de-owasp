"""
api/core/config.py
Configuración centralizada del microservicio API.
Lee variables de entorno con valores por defecto sensatos.
"""
from functools import lru_cache
from typing import List
from pydantic import BaseModel
from dotenv import load_dotenv
import os

load_dotenv()


class APISettings(BaseModel):
    # Identidad del servicio
    api_title: str = os.getenv("API_TITLE", "OWASP Verificador — Microservicio API")
    api_version: str = os.getenv("API_VERSION", "1.0.0")
    api_env: str = os.getenv("APP_ENV", "development")
    api_description: str = (
        "API REST profesional y Skills para IA sobre el sistema OWASP Verificador. "
        "Expone 7 skills listos para tool calling en agentes de IA."
    )

    # Seguridad
    api_key_header: str = os.getenv("API_KEY_HEADER", "X-API-Key")
    require_auth: bool = os.getenv("REQUIRE_AUTH", "false").lower() == "true"

    # CORS — lista separada por comas, "*" para todos
    allowed_origins: List[str] = [
        o.strip()
        for o in os.getenv("ALLOWED_ORIGINS", "*").split(",")
        if o.strip()
    ]

    # Puerto del servidor (informativo, usado por scripts de inicio)
    port: int = int(os.getenv("API_PORT", "8001"))


@lru_cache
def get_api_settings() -> APISettings:
    return APISettings()
