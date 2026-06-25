"""
api/main.py
Punto de entrada del microservicio API para el OWASP Verificador.

Ejecutar con:
    uvicorn api.main:app --reload --port 8001

Swagger UI disponible en: http://localhost:8001/api/docs
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from datetime import datetime, timezone
import logging
import os

from api.core.config import get_api_settings
from api.routes import analyze, reports, exports, stats

# ─── Configuración ────────────────────────────────────────────────────────────

settings = get_api_settings()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("api.main")

# ─── Aplicación FastAPI ───────────────────────────────────────────────────────

app = FastAPI(
    title=settings.api_title,
    description=settings.api_description,
    version=settings.api_version,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    contact={
        "name": "OWASP Verificador",
        "url": "https://github.com/UPT-FAING-EPIS/proyecto-si784-2026-i-u1-verificador-de-cumplimiento-de-owasp",
    },
    license_info={"name": "MIT"},
    openapi_tags=[
        {
            "name": "🔍 Análisis OWASP",
            "description": "Skills de análisis: analiza URLs, código fuente y repos GitHub",
        },
        {
            "name": "📋 Reportes",
            "description": "Skills de reportes: obtén y compara escaneos anteriores",
        },
        {
            "name": "📤 Exportaciones",
            "description": "Skills de exportación: descarga reportes en PDF o JSON",
        },
        {
            "name": "📊 Estadísticas",
            "description": "Skill de dashboard: métricas globales del sistema",
        },
        {
            "name": "🤖 Skills para IA",
            "description": "Mapa de skills disponibles para tool calling en agentes de IA",
        },
        {
            "name": "⚙️ Sistema",
            "description": "Health check e información del microservicio",
        },
    ],
)

# ─── CORS ─────────────────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-Scan-ID", "X-Scan-Score", "Content-Disposition"],
)

# ─── Middleware de logging ────────────────────────────────────────────────────

@app.middleware("http")
async def request_logger(request: Request, call_next):
    start = datetime.now(timezone.utc)
    response = await call_next(request)
    duration_ms = (datetime.now(timezone.utc) - start).total_seconds() * 1000
    logger.info(
        "%s %s → %d (%.1fms)",
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )
    # Añadir headers de identificación del servicio
    response.headers["X-Service"] = "owasp-api"
    response.headers["X-API-Version"] = settings.api_version
    return response


# ─── Manejadores de error globales ────────────────────────────────────────────

@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return JSONResponse(
        status_code=404,
        content={
            "success": False,
            "data": None,
            "message": f"Endpoint no encontrado: {request.url.path}",
        },
    )


@app.exception_handler(500)
async def server_error_handler(request: Request, exc):
    logger.exception("Error interno en %s", request.url.path)
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "data": None,
            "message": "Error interno del servidor",
        },
    )


# ─── Endpoints del sistema ────────────────────────────────────────────────────

@app.get(
    "/api/health",
    tags=["⚙️ Sistema"],
    summary="Health check",
    description="Verifica que el microservicio esté operativo.",
)
async def health_check():
    return {
        "success": True,
        "data": {
            "status": "ok",
            "service": "owasp-api",
            "version": settings.api_version,
            "env": settings.api_env,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "auth_required": settings.require_auth,
        },
        "message": "Microservicio OWASP API operativo",
    }


@app.get(
    "/api/v1/info",
    tags=["⚙️ Sistema"],
    summary="Información del microservicio",
    description="Devuelve metadata completa del microservicio y links útiles.",
)
async def service_info():
    return {
        "success": True,
        "data": {
            "service": "OWASP Verificador — Microservicio API",
            "version": settings.api_version,
            "description": settings.api_description,
            "endpoints": {
                "swagger_ui": "/api/docs",
                "redoc": "/api/redoc",
                "openapi_schema": "/api/openapi.json",
                "health": "/api/health",
                "skills_map": "/api/v1/skills",
            },
            "skills": [
                "skill_analyze_url",
                "skill_analyze_code",
                "skill_analyze_github",
                "skill_get_report",
                "skill_compare_scans",
                "skill_export_pdf",
                "skill_export_json",
                "skill_dashboard_stats",
            ],
            "auth": {
                "required": settings.require_auth,
                "header": settings.api_key_header,
                "demo_token": "demo-token-12345" if not settings.require_auth else "—",
            },
        },
        "message": "OK",
    }


# ─── Routers con prefijo /api/v1/ ─────────────────────────────────────────────

API_V1_PREFIX = "/api/v1"

app.include_router(analyze.router, prefix=API_V1_PREFIX)
app.include_router(reports.router, prefix=API_V1_PREFIX)
app.include_router(exports.router, prefix=API_V1_PREFIX)
app.include_router(stats.router, prefix=API_V1_PREFIX)


# ─── Skill map endpoint (importado dinámicamente para evitar ciclos) ──────────

@app.get(
    "/api/v1/skills",
    tags=["🤖 Skills para IA"],
    summary="Mapa de skills disponibles",
    description=(
        "Devuelve el mapa completo de skills para tool calling en agentes de IA. "
        "Cada skill incluye descripción, endpoint, schema de input/output y ejemplos."
    ),
    operation_id="get_skill_map",
)
async def get_skills():
    from skills.skill_map import SKILL_MAP, get_skills_list
    return {
        "success": True,
        "data": {
            "total_skills": len(SKILL_MAP),
            "base_url": "/api/v1",
            "skills": get_skills_list(),
        },
        "message": f"{len(SKILL_MAP)} skills disponibles para tool calling",
    }


# ─── Punto de entrada directo ────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api.main:app",
        host="0.0.0.0",
        port=settings.port,
        reload=settings.api_env == "development",
        log_level="info",
    )
