"""
api/models/request_models.py
Pydantic schemas para los inputs de la API.
Diseñados para ser usados directamente como tool inputs por agentes de IA.
"""
from typing import Literal, Optional
from pydantic import BaseModel, Field, field_validator
import re


# ─── Análisis ────────────────────────────────────────────────────────────────

class AnalyzeURLRequest(BaseModel):
    """Analiza una URL buscando vulnerabilidades OWASP en sus cabeceras HTTP."""
    url: str = Field(
        ...,
        description="URL completa a analizar (debe incluir http:// o https://)",
        examples=["https://example.com"],
        min_length=7,
    )

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not re.match(r"^https?://", v, re.IGNORECASE):
            raise ValueError("La URL debe comenzar con http:// o https://")
        return v


class AnalyzeCodeRequest(BaseModel):
    """Analiza un fragmento de código fuente buscando vulnerabilidades OWASP."""
    code: str = Field(
        ...,
        description="Código fuente a analizar",
        min_length=1,
        max_length=500_000,
    )
    language: Optional[str] = Field(
        default=None,
        description="Lenguaje del código (informativo, ej: python, javascript)",
        examples=["python", "javascript", "java"],
    )


class AnalyzeGitHubRequest(BaseModel):
    """Analiza un repositorio o archivo de GitHub buscando vulnerabilidades OWASP."""
    repo_url: str = Field(
        ...,
        description="URL del repositorio o archivo en GitHub",
        examples=["https://github.com/owner/repo"],
    )
    create_issues: bool = Field(
        default=False,
        description="Si es true, crea GitHub Issues por cada vulnerabilidad encontrada",
    )
    github_token: Optional[str] = Field(
        default=None,
        description="Token de GitHub para repositorios privados o creación de issues",
    )

    @field_validator("repo_url")
    @classmethod
    def validate_github_url(cls, v: str) -> str:
        v = v.strip()
        if "github.com" not in v:
            raise ValueError("La URL debe ser de GitHub (github.com)")
        return v


# ─── Reportes ────────────────────────────────────────────────────────────────

class CompareScansRequest(BaseModel):
    """Compara dos escaneos previos para ver la evolución de vulnerabilidades."""
    scan_id_left: int = Field(
        ...,
        description="ID del escaneo base (más antiguo)",
        gt=0,
    )
    scan_id_right: int = Field(
        ...,
        description="ID del escaneo a comparar (más reciente)",
        gt=0,
    )


# ─── Exports ──────────────────────────────────────────────────────────────────

class ExportRequest(BaseModel):
    """Solicita la exportación de un reporte en un formato específico."""
    scan_id: int = Field(..., description="ID del escaneo a exportar", gt=0)
    format: Literal["pdf", "json"] = Field(
        default="json",
        description="Formato de exportación: 'pdf' o 'json'",
    )
