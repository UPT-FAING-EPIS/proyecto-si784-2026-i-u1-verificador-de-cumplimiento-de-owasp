from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.store import scan_store

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    scans = scan_store.list_scans()
    
    # Calculate statistics
    total_scans = len(scans)
    total_findings = sum(len(scan.findings) for scan in scans)
    avg_score = round(sum(scan.score for scan in scans) / total_scans, 1) if total_scans > 0 else 0
    high_severity_count = sum(
        1 for scan in scans 
        for finding in scan.findings 
        if finding.severity == 'high'
    )
    
    stats = {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "avg_score": avg_score,
        "high_severity": high_severity_count,
    }
    
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"request": request, "scans": scans, "stats": stats},
    )


@router.get("/about", response_class=HTMLResponse)
def about(request: Request):
    return templates.TemplateResponse(request=request, name="about.html", context={"request": request})


@router.get("/owasp", response_class=HTMLResponse)
def owasp_wiki(request: Request):
    return templates.TemplateResponse(request=request, name="owasp_wiki.html", context={"request": request})


@router.get("/monitoring", response_class=HTMLResponse)
def monitoring_accesses(request: Request):
    accesses = scan_store.list_accesses(limit=100)
    return templates.TemplateResponse(request=request, name="monitoring.html", context={"request": request, "accesses": accesses})
