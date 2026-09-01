import os
from pathlib import Path
from dotenv import load_dotenv

# Search for .env in current directory, backend directory, and project root
env_paths = [
    Path(".env"),
    Path("backend/.env"),
    Path(__file__).resolve().parent.parent.parent / ".env",
    Path(__file__).resolve().parent.parent.parent.parent / ".env",
]

for env_path in env_paths:
    if env_path.exists():
        load_dotenv(dotenv_path=env_path, override=False)

class Settings:
    PROJECT_NAME: str = "Intelligent VAPT Report Analysis & Remediation System"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api"
    
    # Gemini API Settings
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    
    # Database Settings
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./vapt.db")
    
    # Upload Settings
    UPLOAD_DIR: str = os.getenv("UPLOAD_DIR", "uploads")
    
    # Evaluation Settings
    EVALUATION_TIMEOUT_SECONDS: int = int(os.getenv("EVALUATION_TIMEOUT_SECONDS", "30"))

    @property
    def is_gemini_configured(self) -> bool:
        return bool(self.GEMINI_API_KEY and self.GEMINI_API_KEY.strip() and not self.GEMINI_API_KEY.startswith("YOUR_"))

settings = Settings()
