from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "CyberIntel"
    DATABASE_URL: str = "postgresql://cyberadmin:securepassword@localhost:5432/cyberintel"
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # NVD API Key (User should provide this eventually, but we can start without or with a placeholder)
    NVD_API_KEY: str | None = None

    class Config:
        case_sensitive = True
        env_file = ".env"

settings = Settings()
