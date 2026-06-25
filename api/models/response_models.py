"""
api/models/response_models.py
Pydantic schemas de respuesta.
Todas las respuestas usan el envelope APIResponse para consistencia.
"""
from typing import Any, List, Optional
from datetime import datetime
from pydantic import BaseModel


# ─── Envelope estándar ────────────────────────────────────────────────────────

class APIResponse(BaseModel):
    """
    Envelope estándar para todas las respuestas de la API.
    Los agentes de IA siempre deben leer 'data' para el contenido útil.
    """
    success: bool = True
    data: Any = None
    message: str = ""


def ok(data: Any = None, message: str = "OK") -> APIResponse:
    """Helper para crear respuestas exitosas."""
    return APIResponse(success=True, data=data, message=message)


def err(message: str, data: Any = None) -> APIResponse:
    """Helper para crear respuestas de error (nunca lanzadas como excepción)."""
    return APIResponse(success=False, data=data, message=message)


# ─── Modelos de datos ─────────────────────────────────────────────────────────

class FindingOut(BaseModel):
    """Un hallazgo individual de vulnerabilidad OWASP."""
    rule_id: str
    title: str
    severity: str          # "high" | "medium" | "low"
    description: str
    evidence: str
    penalty: int = 0
    remediation: str = ""

    model_config = {"from_attributes": True}


class ScanOut(BaseModel):
    """Resultado completo de un escaneo de seguridad."""
    id: int
    target_type: str       # "url" | "code" | "archivo" | "github_repo"
    target_value: str
    status: str
    score: int             # 0-100 (100 = sin vulnerabilidades)
    created_at: Optional[datetime] = None
    findings: List[FindingOut] = []
    findings_count: int = 0
    severity_summary: dict = {}

    model_config = {"from_attributes": True}

    @classmethod
    def from_scan(cls, scan: Any) -> "ScanOut":
        """Construye ScanOut desde un objeto Scan del store."""
        findings = [
            FindingOut(
                rule_id=f.rule_id,
                title=f.title,
                severity=f.severity,
                description=f.description,
                evidence=f.evidence,
                penalty=getattr(f, "penalty", 0),
                remediation=getattr(f, "remediation", ""),
            )
            for f in scan.findings
        ]
        severity_summary = {"high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f.severity.lower()
            if sev in severity_summary:
                severity_summary[sev] += 1

        return cls(
            id=scan.id,
            target_type=scan.target_type,
            target_value=scan.target_value,
            status=scan.status,
            score=scan.score,
            created_at=scan.created_at,
            findings=findings,
            findings_count=len(findings),
            severity_summary=severity_summary,
        )


class StatsOut(BaseModel):
    """Estadísticas globales del dashboard."""
    total_scans: int
    total_findings: int
    avg_score: float
    high_severity_count: int
    medium_severity_count: int
    low_severity_count: int
    recent_scans: List[dict] = []
    score_trend: List[dict] = []   # [{"scan_id": 1, "score": 85}, ...]


class CompareOut(BaseModel):
    """Resultado de comparación entre dos escaneos."""
    scan_left: ScanOut
    scan_right: ScanOut
    score_delta: int          # positivo = mejoró, negativo = empeoró
    findings_delta: int       # positivo = más hallazgos, negativo = menos
    added_rules: List[str]    # reglas nuevas en right (regresión)
    fixed_rules: List[str]    # reglas resueltas en right (mejora)
    persistent_rules: List[str]  # reglas en ambos
    summary: str              # resumen en texto para IA


class SkillInfo(BaseModel):
    """Definición de un skill para tool calling de IA."""
    name: str
    description: str
    endpoint: str
    method: str
    input_schema: dict
    output_description: str
    example_input: dict
    tags: List[str] = []
