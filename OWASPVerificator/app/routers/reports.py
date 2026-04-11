from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Scan
from app.schemas import ScanOut

router = APIRouter(prefix="/reports")
templates = Jinja2Templates(directory="app/templates")


@router.get("/api/{scan_id}", response_model=ScanOut)
def report_detail_api(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan no encontrado")
    return scan


@router.get("/api", response_model=list[ScanOut])
def report_list_api(limit: int = 20, db: Session = Depends(get_db)):
    safe_limit = min(max(limit, 1), 100)
    scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(safe_limit).all()
    return scans


@router.get("/{scan_id}", response_class=HTMLResponse)
def report_detail(request: Request, scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan no encontrado")
    return templates.TemplateResponse(request=request, name="report.html", context={"request": request, "scan": scan})
