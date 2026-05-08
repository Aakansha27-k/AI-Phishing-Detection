from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    DATABASE_URL: str = "sqlite:///phishguard.db" # Default for local dev
    REDIS_URL: str = "redis://localhost:6379/0"
    
    VT_API_KEY: Optional[str] = None
    GOOGLE_SAFE_BROWSING_KEY: Optional[str] = None

    class Config:
        env_file = ".env"

settings = Settings()
