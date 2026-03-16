"""
CyberShield AI - Configuration Module
Loads environment variables and provides typed settings.
"""
import os
from pathlib import Path
from functools import lru_cache
from pydantic_settings import BaseSettings
from pydantic import Field

# Project root directory
BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # App settings
    app_name: str = "CyberShield AI"
    app_version: str = "1.0.0"
    app_env: str = Field(default="development", alias="APP_ENV")
    app_debug: bool = Field(default=True, alias="APP_DEBUG")
    app_host: str = Field(default="0.0.0.0", alias="APP_HOST")
    app_port: int = Field(default=8000, alias="APP_PORT")

    # API Keys
    virustotal_api_key: str = Field(default="", alias="VIRUSTOTAL_API_KEY")
    google_safe_browsing_api_key: str = Field(default="", alias="GOOGLE_SAFE_BROWSING_API_KEY")
    reality_defender_api_key: str = Field(default="", alias="REALITY_DEFENDER_API_KEY")
    groq_api_key: str = Field(default="", alias="GROQ_API_KEY")
    serp_api_key: str = Field(default="", alias="SERP_API_KEY")

    # Groq LLM Settings
    groq_model: str = "llama-3.3-70b-versatile"
    groq_max_tokens: int = 2048
    groq_temperature: float = 0.3

    # Detection Thresholds
    phishing_threshold: float = 0.6
    url_threat_threshold: float = 0.5
    deepfake_threshold: float = 0.7
    prompt_injection_threshold: float = 0.5
    anomaly_threshold: float = 0.6

    # Cross-validation settings
    min_agent_agreement: int = 2
    false_positive_reduction_weight: float = 0.8

    model_config = {
        "env_file": str(BASE_DIR / ".env"),
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
        "extra": "ignore",
    }


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
