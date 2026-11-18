import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str = "B2B Travel Booking Service"
    HOST: str = "127.0.0.1"
    PORT: int = 8001
    
    # Toggle for intentional security and business logic vulnerabilities
    BUGS_ENABLED: bool = os.getenv("BUGS_ENABLED", "true").lower() in ("true", "1", "yes")
    FIXED_MODE: bool = os.getenv("FIXED_MODE", "false").lower() in ("true", "1", "yes")
    
    SECRET_KEY: str = "secret-b2b-travel-jwt-token-key-2026"
    ALGORITHM: str = "HS256"

    def is_buggy(self) -> bool:
        if self.FIXED_MODE:
            return False
        return self.BUGS_ENABLED

settings = Settings()
