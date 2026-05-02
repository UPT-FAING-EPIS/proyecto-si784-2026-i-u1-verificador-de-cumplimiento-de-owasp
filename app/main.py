from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles

from app.config import get_settings
from app.routers.analysis import router as analysis_router
from app.routers.dashboard import router as dashboard_router
from app.routers.reports import router as reports_router
from app.store import scan_store

settings = get_settings()
app = FastAPI(title=settings.app_title)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

@app.middleware("http")
async def access_logger(request: Request, call_next):
    client = request.client.host if request.client else "unknown"
    ua = request.headers.get("user-agent", "")
    try:
        scan_store.log_access(path=str(request.url.path), ip=client, user_agent=ua)
    except Exception:
        pass
    response = await call_next(request)
    return response

@app.get("/health")
def health_check():
    return {"status": "ok", "env": settings.app_env}


app.include_router(dashboard_router)
app.include_router(analysis_router)
app.include_router(reports_router)
