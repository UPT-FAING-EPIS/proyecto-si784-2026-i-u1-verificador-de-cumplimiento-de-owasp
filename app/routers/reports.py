from pathlib import Path
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.schemas import ScanOut
from app.store import scan_store

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


@router.get("/{scan_id}", response_class=HTMLResponse)
def report_detail(request: Request, scan_id: int):
    scan = scan_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan no encontrado")
    return templates.TemplateResponse(request=request, name="report.html", context={"request": request, "scan": scan})
