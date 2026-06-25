"""
api/routes/reports.py
Endpoints de reportes — skills: skill_get_report, skill_compare_scans
"""
from typing import List
from fastapi import APIRouter, Depends, Query

from api.core.security import get_current_user
from api.models.request_models import CompareScansRequest
from api.models.response_models import APIResponse, ScanOut, CompareOut, ok
from api.services import report_service

router = APIRouter(prefix="/reports", tags=["📋 Reportes"])


@router.get(
    "",
    response_model=APIResponse,
    summary="Listar todos los escaneos",
    description="Devuelve la lista de escaneos más recientes. Máximo 100 resultados.",
    operation_id="list_reports",
)
async def list_reports(
    limit: int = Query(default=20, ge=1, le=100, description="Número máximo de resultados"),
    user: str = Depends(get_current_user),
) -> APIResponse:
    scans = report_service.list_scans(limit=limit)
    data = [ScanOut.from_scan(s).model_dump() for s in scans]
    return ok(data=data, message=f"{len(data)} escaneo(s) encontrado(s)")


@router.get(
    "/{scan_id}",
    response_model=APIResponse,
    summary="skill_get_report — Obtener reporte por ID",
    description=(
        "**Skill para IA**: Obtiene el reporte completo de un escaneo específico. "
        "Incluye score, todos los hallazgos con severidad y remediaciones detalladas."
    ),
    operation_id="skill_get_report",
)
async def get_report(
    scan_id: int,
    user: str = Depends(get_current_user),
) -> APIResponse:
    """
    Obtiene un reporte de escaneo por ID.

    **Input**: scan_id como parámetro de path.

    **Output**: Reporte completo con score, findings y resumen de severidades.
    """
    scan = report_service.get_scan_or_404(scan_id)
    scan_out = ScanOut.from_scan(scan)
    return ok(
        data=scan_out.model_dump(),
        message=f"Reporte #{scan_id}. Score: {scan.score}/100. "
                f"Hallazgos: {scan_out.findings_count}",
    )


@router.post(
    "/compare",
    response_model=APIResponse,
    summary="skill_compare_scans — Comparar dos escaneos",
    description=(
        "**Skill para IA**: Compara dos escaneos para evaluar la evolución de la seguridad. "
        "Devuelve delta de score, vulnerabilidades resueltas, nuevas y persistentes. "
        "Incluye un resumen en texto natural para que la IA lo interprete directamente."
    ),
    operation_id="skill_compare_scans",
)
async def compare_scans(
    payload: CompareScansRequest,
    user: str = Depends(get_current_user),
) -> APIResponse:
    """
    Compara dos escaneos y devuelve métricas de evolución de seguridad.

    **Input**: `{"scan_id_left": 1, "scan_id_right": 3}`

    **Output**: Delta de score, reglas nuevas/resueltas/persistentes y resumen en texto.
    """
    result = report_service.compare_scans(
        scan_id_left=payload.scan_id_left,
        scan_id_right=payload.scan_id_right,
    )
    compare_out = CompareOut(
        scan_left=ScanOut.from_scan(result["scan_left"]),
        scan_right=ScanOut.from_scan(result["scan_right"]),
        score_delta=result["score_delta"],
        findings_delta=result["findings_delta"],
        added_rules=result["added_rules"],
        fixed_rules=result["fixed_rules"],
        persistent_rules=result["persistent_rules"],
        summary=result["summary"],
    )
    return ok(
        data=compare_out.model_dump(),
        message=result["summary"],
    )
