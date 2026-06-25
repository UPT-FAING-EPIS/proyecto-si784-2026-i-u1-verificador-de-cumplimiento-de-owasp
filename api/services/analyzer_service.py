"""
api/services/analyzer_service.py
Wrapper del servicio de análisis original.
Traduce excepciones internas a HTTPException de FastAPI.
NO contiene lógica de negocio propia — delega completamente a app.services.
"""
import logging
from fastapi import HTTPException, status

from app.services.analysis_service import execute_scan as _execute_scan
from app.models import Scan

logger = logging.getLogger("api.analyzer_service")


def analyze_url(url: str) -> Scan:
    """
    Ejecuta un análisis OWASP sobre una URL.
    Verifica cabeceras HTTP de seguridad.
    Devuelve el objeto Scan persistido.
    """
    logger.info("skill_analyze_url | url=%s", url)
    try:
        return _execute_scan(target_type="url", target_value=url)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Error inesperado en analyze_url")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error interno al analizar la URL: {exc}",
        ) from exc


def analyze_code(code: str) -> Scan:
    """
    Ejecuta un análisis OWASP sobre código fuente.
    Detecta patrones de las 10 categorías OWASP Top 10.
    Devuelve el objeto Scan persistido.
    """
    logger.info("skill_analyze_code | chars=%d", len(code))
    try:
        return _execute_scan(target_type="code", target_value=code)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Error inesperado en analyze_code")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error interno al analizar el código: {exc}",
        ) from exc


def analyze_github(
    repo_url: str,
    create_issues: bool = False,
    github_token: str | None = None,
) -> Scan:
    """
    Descarga y analiza un repositorio de GitHub.
    Soporta repos públicos y privados (con token).
    Opcionalmente crea GitHub Issues por cada vulnerabilidad.
    """
    logger.info(
        "skill_analyze_github | url=%s create_issues=%s",
        repo_url,
        create_issues,
    )
    try:
        return _execute_scan(
            target_type="github_repo",
            target_value=repo_url,
            create_issues=create_issues,
            github_token=github_token,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Error inesperado en analyze_github")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error interno al analizar el repositorio: {exc}",
        ) from exc
