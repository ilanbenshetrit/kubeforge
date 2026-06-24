"""
kubeforge/config.py
────────────────────
Central configuration for the KubeForge platform.
All settings are loaded from environment variables (or a .env file).
Uses pydantic-settings so every value is type-validated at startup.
"""

from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    # ── General ──────────────────────────────────────────────────────────
    app_name: str = Field(default="KubeForge Security Platform", alias="APP_NAME")
    version: str = Field(default="0.1.0", alias="VERSION")
    environment: str = Field(default="development", alias="ENVIRONMENT")  # development | production
    debug: bool = Field(default=False, alias="DEBUG")

    # ── API Server ────────────────────────────────────────────────────────
    api_host: str = Field(default="0.0.0.0", alias="API_HOST")
    api_port: int = Field(default=8080, alias="API_PORT")
    api_secret_key: str = Field(default="change-me-in-production", alias="API_SECRET_KEY")

    # ── AI Co-Pilot ───────────────────────────────────────────────────────
    openai_api_key: str = Field(default="", alias="OPENAI_API_KEY")
    openai_model: str = Field(default="gpt-4o", alias="OPENAI_MODEL")
    copilot_language: str = Field(default="hebrew", alias="COPILOT_LANGUAGE")  # hebrew | english

    # ── Scanner ───────────────────────────────────────────────────────────
    scan_interval_seconds: int = Field(default=60, alias="SCAN_INTERVAL_SECONDS")
    scan_target_paths: list[str] = Field(default=["/data", "/tmp"], alias="SCAN_TARGET_PATHS")
    max_file_size_mb: int = Field(default=50, alias="MAX_FILE_SIZE_MB")

    # ── Network Scanner ───────────────────────────────────────────────────
    network_scan_hosts: list[str] = Field(default=[], alias="NETWORK_SCAN_HOSTS")

    # ── Alerts ────────────────────────────────────────────────────────────
    alert_email: str = Field(default="", alias="ALERT_EMAIL")
    slack_webhook_url: str = Field(default="", alias="SLACK_WEBHOOK_URL")

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "populate_by_name": True,
    }


# Singleton — import this everywhere
settings = Settings()
