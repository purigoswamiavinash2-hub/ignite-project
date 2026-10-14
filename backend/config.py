import os

class Settings:
    PROJECT_NAME: str = "ThreatGuard AI"
    API_V1_STR: str = "/api"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "threatguard-super-secret-key-change-in-production")
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./threatguard.db")
    CORS_ORIGINS: list = ["*"]
    MODEL_PATH: str = os.path.join(os.path.dirname(__file__), "ml_model.joblib")
    MAX_REQUEST_SIZE_BYTES: int = 100 * 1024  # 100 KB limit for input scanning

settings = Settings()
