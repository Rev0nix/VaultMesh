from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "VaultMesh"
    APP_VERSION: str = "0.1.0"
    APP_ENV: str = "development"
    API_V1_PREFIX: str = "/api/v1"
    SECRET_KEY: str = "dev-insecure-secret-key-replace-in-prod"
    DATABASE_URL: str = "sqlite:///./vaultmesh.db"
    BACKEND_CORS_ORIGINS: list[str] = ["http://localhost:5173"]
    AWS_INTEGRATION_MODE: str = "mock"
    AWS_DEFAULT_REGION: str = "ap-south-1"

    model_config = SettingsConfigDict(
        env_file="../.env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
