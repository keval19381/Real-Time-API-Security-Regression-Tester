import os
from pydantic_settings import BaseSettings

class BackendSettings(BaseSettings):
    APP_NAME: str = "DAST Change Detection & API Inventory Service"
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    TARGET_APP_URL: str = os.getenv("TARGET_APP_URL", "http://127.0.0.1:8001")
    DB_PATH: str = os.getenv("INVENTORY_DB_PATH", "backend_inventory.sqlite")
    TRAFFIC_LOGS_PATH: str = os.getenv("TRAFFIC_LOGS_PATH", "traffic_logs.jsonl")

backend_settings = BackendSettings()
