"""
api/services/report_service.py
Wrapper del store de escaneos para la capa API.
Encapsula acceso a scan_store y lógica de comparación de scans.
"""
import logging
from typing import List, Optional
from fastapi import HTTPException, status

from app.store import scan_store
from app.models import Scan

logger = logging.getLogger("api.report_service")


def get_scan_or_404(scan_id: int) -> Scan:
    """Obtiene un scan por ID o lanza HTTP 404."""
    scan = scan_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Escaneo #{scan_id} no encontrado",
        )
    return scan


def list_scans(limit: int = 20) -> List[Scan]:
    """Lista los escaneos más recientes con un límite máximo de 100."""
    safe_limit = min(max(limit, 1), 100)
    return scan_store.list_scans(limit=safe_limit)


def compare_scans(scan_id_left: int, scan_id_right: int) -> dict:
    """
    Compara dos escaneos y devuelve un dict con métricas de evolución.
    skill_compare_scans — ideal para que una IA evalúe el progreso de seguridad.
    """
    left = get_scan_or_404(scan_id_left)
    right = get_scan_or_404(scan_id_right)

    left_rules = {f.rule_id: f for f in left.findings}
    right_rules = {f.rule_id: f for f in right.findings}

    added_rules = sorted(set(right_rules.keys()) - set(left_rules.keys()))
    fixed_rules = sorted(set(left_rules.keys()) - set(right_rules.keys()))
    persistent_rules = sorted(set(left_rules.keys()) & set(right_rules.keys()))

    score_delta = right.score - left.score
    findings_delta = len(right.findings) - len(left.findings)

    # Resumen en texto natural para que la IA lo interprete fácilmente
    if score_delta > 0:
        trend = f"⬆️ Mejoró {score_delta} puntos"
    elif score_delta < 0:
        trend = f"⬇️ Empeoró {abs(score_delta)} puntos"
    else:
        trend = "➡️ Sin cambios en el score"

    summary_parts = [trend]
    if fixed_rules:
        summary_parts.append(f"✅ Vulnerabilidades resueltas: {', '.join(fixed_rules)}")
    if added_rules:
        summary_parts.append(f"🆕 Nuevas vulnerabilidades: {', '.join(added_rules)}")
    if persistent_rules:
        summary_parts.append(f"⚠️ Persistentes: {', '.join(persistent_rules)}")

    return {
        "scan_left": left,
        "scan_right": right,
        "score_delta": score_delta,
        "findings_delta": findings_delta,
        "added_rules": added_rules,
        "fixed_rules": fixed_rules,
        "persistent_rules": persistent_rules,
        "summary": " | ".join(summary_parts),
    }
