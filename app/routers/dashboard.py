from pathlib import Path
import os
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.store import scan_store

router = APIRouter()
templates_dir = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))
ADMIN_DASHBOARD_PASSWORD = os.getenv("ADMIN_DASHBOARD_PASSWORD", "owasp-admin-2026")


@router.get("/admin/login", response_class=HTMLResponse)
def admin_login_form(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="admin_login.html",
        context={"request": request, "error": None},
    )


@router.post("/admin/login", response_class=HTMLResponse)
def admin_login(request: Request, password: str = Form(...)):
    if password != ADMIN_DASHBOARD_PASSWORD:
        return templates.TemplateResponse(
            request=request,
            name="admin_login.html",
            context={"request": request, "error": "Contrasena incorrecta."},
            status_code=401,
        )

    session_id = scan_store.create_admin_session("admin")
    response = RedirectResponse(url="/admin", status_code=303)
    response.set_cookie(
        key="admin_session",
        value=session_id,
        httponly=True,
        samesite="lax",
        max_age=6 * 60 * 60,
    )
    return response


@router.get("/admin/logout")
def admin_logout(request: Request):
    session_id = request.cookies.get("admin_session")
    scan_store.revoke_admin_session(session_id)
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie("admin_session")
    return response


@router.post("/admin/github-token", response_class=HTMLResponse)
def save_github_token(request: Request, github_token: str = Form(...)):
    """Save GitHub token from admin panel."""
    if not scan_store.validate_admin_session(request.cookies.get("admin_session")):
        return RedirectResponse(url="/admin/login", status_code=303)
    
    # Save token to store
    scan_store.set_github_token(github_token if github_token.strip() else None)
    
    # Redirect back to admin dashboard
    return RedirectResponse(url="/admin", status_code=303)


@router.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request):
    """Dashboard de administrador con estadísticas y control."""
    if not scan_store.validate_admin_session(request.cookies.get("admin_session")):
        return RedirectResponse(url="/admin/login", status_code=303)

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
    
    # Build risk matrix
    risk_matrix = {"high": [0, 0, 0, 0], "medium": [0, 0, 0, 0], "low": [0, 0, 0, 0]}
    for scan in scans:
        for finding in scan.findings:
            severity = finding.severity
            # Count occurrences of each rule
            count = sum(1 for f in scan.findings if f.rule_id == finding.rule_id and f.severity == severity)
            if count > 10:
                idx = 0
            elif count > 5:
                idx = 1
            elif count > 2:
                idx = 2
            else:
                idx = 3
            if risk_matrix[severity][idx] < count:
                risk_matrix[severity][idx] = count
    
    # Get tokens and accesses
    tokens = scan_store.get_all_tokens()
    accesses = scan_store.list_accesses(limit=100)
    
    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context={
            "request": request,
            "stats": stats,
            "risk_matrix": risk_matrix,
            "tokens": tokens,
            "accesses": accesses,
            "scans_data": [{"id": s.id, "score": s.score} for s in scans[-10:]],
            "github_token_configured": scan_store.has_github_token(),
        },
    )


@router.get("/api-tutorial", response_class=HTMLResponse)
def api_tutorial(request: Request):
    """Página con tutorial de integración de la API."""
    return templates.TemplateResponse(
        request=request,
        name="api_tutorial.html",
        context={"request": request},
    )


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
    # Fetch recent accesses and deduplicate by IP (keep most recent per IP)
    accesses = scan_store.list_accesses(limit=1000)
    seen = set()
    unique_accesses = []
    for a in accesses:
        ip = a.get("ip")
        if not ip:
            continue
        if ip in seen:
            continue
        seen.add(ip)
        unique_accesses.append(a)

    return templates.TemplateResponse(request=request, name="monitoring.html", context={"request": request, "accesses": unique_accesses})
