import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "VAPT Report Analyzer"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "super-secret-security-key-for-vapt-analyzer-app")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    
    # SQLite fallback, PostgreSQL configuration path
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./vapt.db")
    
    # CORS Configuration
    CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]

    class Config:
        env_file = ".env"

settings = Settings()
