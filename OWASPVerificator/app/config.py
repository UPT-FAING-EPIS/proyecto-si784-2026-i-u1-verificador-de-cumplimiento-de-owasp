from functools import lru_cache
from pydantic import BaseModel
from dotenv import load_dotenv
import os

load_dotenv()


class Settings(BaseModel):
    database_url: str = os.getenv("DATABASE_URL", "mysql+pymysql://root:password@127.0.0.1:3306/owasp_verificator")
    app_title: str = os.getenv("APP_TITLE", "OWASP Verificator")
    app_env: str = os.getenv("APP_ENV", "development")


@lru_cache
def get_settings() -> Settings:
    return Settings()
