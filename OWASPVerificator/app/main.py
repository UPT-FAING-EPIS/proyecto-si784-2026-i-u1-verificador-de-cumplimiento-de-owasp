from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.config import get_settings
from app.db import Base, engine
from app.routers.analysis import router as analysis_router
from app.routers.dashboard import router as dashboard_router
from app.routers.reports import router as reports_router

settings = get_settings()
app = FastAPI(title=settings.app_title)
app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)


@app.get("/health")
def health_check():
    return {"status": "ok", "env": settings.app_env}


app.include_router(dashboard_router)
app.include_router(analysis_router)
app.include_router(reports_router)
