from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "ThreatHunter"
    environment: str = "development"
    debug: bool = False

    model_config = SettingsConfigDict(
        env_prefix="THREATHUNTER_",
        env_file=".env",
        extra="ignore",
    )


settings = Settings()
