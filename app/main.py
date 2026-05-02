from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from typing import Optional

from app.config import get_settings
from app.routers.analysis import router as analysis_router
from app.routers.dashboard import router as dashboard_router
from app.routers.reports import router as reports_router
from app.store import scan_store

settings = get_settings()
app = FastAPI(
    title=settings.app_title,
    description="Verificador de Cumplimiento OWASP - Herramienta de análisis de seguridad",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Ruta absoluta para archivos estáticos
static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

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
    """Health check endpoint - verifica que el servicio está operativo."""
    return {"status": "ok", "env": settings.app_env}


@app.post("/api/token")
def generate_api_token(user: str):
    """Genera un nuevo token API para el usuario especificado."""
    if not user or len(user) < 2:
        raise HTTPException(status_code=400, detail="Usuario inválido")
    token = scan_store.generate_token(user)
    return {"token": token, "user": user, "message": "Token generado exitosamente"}


@app.get("/api/validate-token")
def validate_api_token(x_api_key: Optional[str] = Header(None)):
    """Valida un token API y retorna información del usuario."""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Token no proporcionado")
    
    result = scan_store.validate_token(x_api_key)
    if not result:
        raise HTTPException(status_code=401, detail="Token inválido o expirado")
    
    return result


app.include_router(dashboard_router)
app.include_router(analysis_router)
app.include_router(reports_router)
