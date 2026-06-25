"""
api/routes/exports.py
Endpoints de exportación — skills: skill_export_pdf, skill_export_json
"""
from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse, JSONResponse

from api.core.security import get_current_user
from api.models.response_models import APIResponse, ok
from api.services import report_service, export_service

router = APIRouter(prefix="/exports", tags=["📤 Exportaciones"])


@router.get(
    "/{scan_id}/pdf",
    summary="skill_export_pdf — Exportar reporte en PDF",
    description=(
        "**Skill para IA**: Genera y descarga el reporte de seguridad en formato PDF "
        "con diseño profesional. Incluye score, tabla de hallazgos y remediaciones."
    ),
    operation_id="skill_export_pdf",
    responses={
        200: {
            "content": {"application/pdf": {}},
            "description": "Archivo PDF del reporte de seguridad",
        }
    },
)
async def export_pdf(
    scan_id: int,
    user: str = Depends(get_current_user),
):
    """
    Exporta un reporte de escaneo como PDF.

    **Input**: scan_id como parámetro de path.

    **Output**: Archivo PDF descargable (StreamingResponse).
    """
    scan = report_service.get_scan_or_404(scan_id)
    pdf_buffer = export_service.export_pdf(scan)
    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=owasp-report-{scan_id}.pdf",
            "X-Scan-ID": str(scan_id),
            "X-Scan-Score": str(scan.score),
        },
    )


@router.get(
    "/{scan_id}/json",
    response_model=APIResponse,
    summary="skill_export_json — Exportar reporte en JSON",
    description=(
        "**Skill para IA**: Devuelve el reporte completo en formato JSON estructurado, "
        "listo para integración con sistemas externos, SIEM, dashboards, etc. "
        "Incluye metadata de exportación con timestamp."
    ),
    operation_id="skill_export_json",
)
async def export_json(
    scan_id: int,
    user: str = Depends(get_current_user),
) -> APIResponse:
    """
    Exporta un reporte de escaneo como JSON estructurado.

    **Input**: scan_id como parámetro de path.

    **Output**: JSON con metadata, score, hallazgos y resumen de severidades.
    """
    scan = report_service.get_scan_or_404(scan_id)
    data = export_service.export_json(scan)
    return ok(
        data=data,
        message=f"Exportación JSON del escaneo #{scan_id} completada",
    )
