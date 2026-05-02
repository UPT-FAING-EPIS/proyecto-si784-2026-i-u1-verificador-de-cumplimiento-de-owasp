from pathlib import Path
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.schemas import AnalyzeRequest, ScanOut
from app.services.analysis_service import execute_scan

router = APIRouter(prefix="/analyze")
templates_dir = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))


@router.get("", response_class=HTMLResponse)
def analyze_form(request: Request):
    return templates.TemplateResponse(request=request, name="analyze.html", context={"request": request})


@router.post("", response_class=HTMLResponse)
def analyze(
    request: Request,
    target_type: str = Form(...),
    target_value: str = Form(...),
):
    try:
        scan = execute_scan(target_type=target_type, target_value=target_value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return RedirectResponse(url=f"/reports/{scan.id}", status_code=303)


@router.post("/api", response_model=ScanOut)
def analyze_api(payload: AnalyzeRequest):
    try:
        return execute_scan(target_type=payload.target_type, target_value=payload.target_value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
