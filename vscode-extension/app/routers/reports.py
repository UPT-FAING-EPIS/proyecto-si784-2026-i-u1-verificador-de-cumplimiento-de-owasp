from pathlib import Path
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

from app.schemas import ScanOut
from app.store import scan_store
from app.services.pdf_export import export_scan_to_pdf

router = APIRouter(prefix="/reports")
templates_dir = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))


@router.get("/api/{scan_id}", response_model=ScanOut)
def report_detail_api(scan_id: int):
    scan = scan_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan no encontrado")
    return scan


@router.get("/api", response_model=list[ScanOut])
def report_list_api(limit: int = 20):
    safe_limit = min(max(limit, 1), 100)
    return scan_store.list_scans(limit=safe_limit)


@router.get("/{scan_id}/export-pdf")
def export_report_pdf(scan_id: int):
    """Exporta un reporte de escaneo como PDF."""
    scan = scan_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan no encontrado")
    
    pdf_buffer = export_scan_to_pdf(scan)
    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=reporte-seguridad-{scan.id}.pdf"
        },
    )


@router.get("/compare", response_class=HTMLResponse)
def compare_reports(request: Request, left_id: int | None = None, right_id: int | None = None):
    """Compara dos escaneos y muestra diferencias de score y hallazgos."""
    scans = scan_store.list_scans(limit=100)
    left_scan = scan_store.get_scan(left_id) if left_id else None
    right_scan = scan_store.get_scan(right_id) if right_id else None

    comparison = None
    if left_scan and right_scan:
        left_rules = {f.rule_id: f for f in left_scan.findings}
        right_rules = {f.rule_id: f for f in right_scan.findings}
        added_rules = sorted(set(right_rules.keys()) - set(left_rules.keys()))
        fixed_rules = sorted(set(left_rules.keys()) - set(right_rules.keys()))
        persistent_rules = sorted(set(left_rules.keys()) & set(right_rules.keys()))

        comparison = {
            "score_delta": right_scan.score - left_scan.score,
            "findings_delta": len(right_scan.findings) - len(left_scan.findings),
            "left": left_scan,
            "right": right_scan,
            "added_rules": added_rules,
            "fixed_rules": fixed_rules,
            "persistent_rules": persistent_rules,
        }

    return templates.TemplateResponse(
        request=request,
        name="compare.html",
        context={
            "request": request,
            "scans": scans,
            "left_id": left_id,
            "right_id": right_id,
            "comparison": comparison,
        },
    )


@router.get("/{scan_id}/export-json")
def export_report_json(scan_id: int):
    """Exporta un reporte de escaneo como JSON."""
    scan = scan_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan no encontrado")
    
    return {
        "scan_id": scan.id,
        "target_type": scan.target_type,
        "target_value": scan.target_value,
        "score": scan.score,
        "created_at": scan.created_at.isoformat(),
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "description": f.description,
                "evidence": f.evidence,
                "penalty": f.penalty,
                "remediation": f.remediation,
            }
            for f in scan.findings
        ]
    }


@router.get("/{scan_id}", response_class=HTMLResponse)
def report_detail(request: Request, scan_id: int):
    scan = scan_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan no encontrado")
    return templates.TemplateResponse(request=request, name="report.html", context={"request": request, "scan": scan})
