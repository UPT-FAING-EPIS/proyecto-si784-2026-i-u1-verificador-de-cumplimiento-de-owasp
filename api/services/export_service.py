"""
api/services/export_service.py
Wrapper de los exportadores originales (PDF y JSON).
La lógica de generación vive en app/services/pdf_export.py.
"""
import logging
import json
from io import BytesIO
from datetime import datetime
from fastapi import HTTPException, status

from app.services.pdf_export import export_scan_to_pdf as _export_pdf
from app.models import Scan

logger = logging.getLogger("api.export_service")


def export_pdf(scan: Scan) -> BytesIO:
    """
    Genera un PDF del reporte de seguridad.
    skill_export_pdf — devuelve bytes del PDF listos para StreamingResponse.
    """
    logger.info("skill_export_pdf | scan_id=%d", scan.id)
    try:
        return _export_pdf(scan)
    except Exception as exc:
        logger.exception("Error generando PDF para scan %d", scan.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al generar el PDF: {exc}",
        ) from exc


def export_json(scan: Scan) -> dict:
    """
    Serializa el escaneo como JSON estructurado.
    skill_export_json — ideal para integración con sistemas externos.
    """
    logger.info("skill_export_json | scan_id=%d", scan.id)
    try:
        return {
            "exported_at": datetime.utcnow().isoformat() + "Z",
            "scan_id": scan.id,
            "target_type": scan.target_type,
            "target_value": scan.target_value,
            "status": scan.status,
            "score": scan.score,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "findings_count": len(scan.findings),
            "severity_summary": _severity_summary(scan),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity,
                    "description": f.description,
                    "evidence": f.evidence,
                    "penalty": getattr(f, "penalty", 0),
                    "remediation": getattr(f, "remediation", ""),
                }
                for f in scan.findings
            ],
        }
    except Exception as exc:
        logger.exception("Error generando JSON para scan %d", scan.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al generar el JSON: {exc}",
        ) from exc


def _severity_summary(scan: Scan) -> dict:
    summary = {"high": 0, "medium": 0, "low": 0}
    for f in scan.findings:
        sev = getattr(f, "severity", "low").lower()
        if sev in summary:
            summary[sev] += 1
    return summary
