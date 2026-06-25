"""
api/routes/stats.py
Endpoint de estadísticas — skill: skill_dashboard_stats
"""
from fastapi import APIRouter, Depends

from api.core.security import get_current_user
from api.models.response_models import APIResponse, StatsOut, ok
from app.store import scan_store

router = APIRouter(prefix="/stats", tags=["📊 Estadísticas"])


@router.get(
    "",
    response_model=APIResponse,
    summary="skill_dashboard_stats — Estadísticas globales",
    description=(
        "**Skill para IA**: Devuelve estadísticas globales del sistema: "
        "total de escaneos, hallazgos, score promedio, distribución por severidad "
        "y tendencia de los últimos 10 escaneos. "
        "Ideal para que una IA genere un resumen ejecutivo de seguridad."
    ),
    operation_id="skill_dashboard_stats",
)
async def dashboard_stats(
    user: str = Depends(get_current_user),
) -> APIResponse:
    """
    Obtiene estadísticas globales de todos los escaneos realizados.

    **Input**: ninguno (GET request).

    **Output**: Total scans, findings, score promedio, distribución de severidades,
    últimos 10 scans con ID y score para visualizar tendencia.
    """
    scans = scan_store.list_scans()

    total_scans = len(scans)
    total_findings = sum(len(s.findings) for s in scans)
    avg_score = round(sum(s.score for s in scans) / total_scans, 1) if total_scans > 0 else 0.0

    high_count = sum(
        1 for s in scans for f in s.findings if f.severity == "high"
    )
    medium_count = sum(
        1 for s in scans for f in s.findings if f.severity == "medium"
    )
    low_count = sum(
        1 for s in scans for f in s.findings if f.severity == "low"
    )

    # Tendencia: últimos 10 escaneos en orden cronológico (más antiguo primero)
    recent = scans[:10]
    score_trend = [
        {
            "scan_id": s.id,
            "score": s.score,
            "target_type": s.target_type,
            "findings_count": len(s.findings),
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in reversed(recent)
    ]

    stats = StatsOut(
        total_scans=total_scans,
        total_findings=total_findings,
        avg_score=avg_score,
        high_severity_count=high_count,
        medium_severity_count=medium_count,
        low_severity_count=low_count,
        recent_scans=[
            {"scan_id": s.id, "score": s.score, "target_type": s.target_type}
            for s in scans[:5]
        ],
        score_trend=score_trend,
    )

    # Resumen en texto para IA
    if total_scans == 0:
        summary = "Sin escaneos registrados aún."
    else:
        risk_level = "🟢 BAJO" if avg_score >= 80 else ("🟡 MEDIO" if avg_score >= 50 else "🔴 ALTO")
        summary = (
            f"Riesgo general: {risk_level}. "
            f"{total_scans} escaneos realizados. "
            f"Score promedio: {avg_score}/100. "
            f"Hallazgos: {high_count} críticos, {medium_count} medios, {low_count} bajos."
        )

    return ok(data=stats.model_dump(), message=summary)
