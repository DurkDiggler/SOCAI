from __future__ import annotations

from typing import List, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Server
    app_host: str = Field(default="0.0.0.0", env="APP_HOST")
    app_port: int = Field(default=8000, env="APP_PORT")

    # Feature flags
    enable_email: bool = Field(default=True, env="ENABLE_EMAIL")
    enable_autotask: bool = Field(default=True, env="ENABLE_AUTOTASK")

    # Email
    smtp_host: Optional[str] = Field(default=None, env="SMTP_HOST")
    smtp_port: int = Field(default=587, env="SMTP_PORT")
    smtp_username: Optional[str] = Field(default=None, env="SMTP_USERNAME")
    smtp_password: Optional[str] = Field(default=None, env="SMTP_PASSWORD")
    email_from: Optional[str] = Field(default=None, env="EMAIL_FROM")
    email_to: List[str] = Field(default_factory=list, env="EMAIL_TO")

    # Autotask
    at_base_url: Optional[str] = Field(default=None, env="AT_BASE_URL")
    at_api_integration_code: Optional[str] = Field(default=None, env="AT_API_INTEGRATION_CODE")
    at_username: Optional[str] = Field(default=None, env="AT_USERNAME")
    at_secret: Optional[str] = Field(default=None, env="AT_SECRET")
    at_account_id: Optional[int] = Field(default=None, env="AT_ACCOUNT_ID")
    at_queue_id: Optional[int] = Field(default=None, env="AT_QUEUE_ID")
    at_ticket_priority: int = Field(default=3, env="AT_TICKET_PRIORITY")

    # Threat feeds
    otx_api_key: Optional[str] = Field(default=None, env="OTX_API_KEY")
    vt_api_key: Optional[str] = Field(default=None, env="VT_API_KEY")
    abuseipdb_api_key: Optional[str] = Field(default=None, env="ABUSEIPDB_API_KEY")

    # Scoring
    score_high: int = Field(default=70, env="SCORE_HIGH")
    score_medium: int = Field(default=40, env="SCORE_MEDIUM")

    # HTTP / Cache
    http_timeout: float = Field(default=8.0, env="HTTP_TIMEOUT")
    ioc_cache_ttl: int = Field(default=1800, env="IOC_CACHE_TTL")

    # Webhook auth
    webhook_shared_secret: Optional[str] = Field(default=None, env="WEBHOOK_SHARED_SECRET")
    webhook_hmac_secret: Optional[str] = Field(default=None, env="WEBHOOK_HMAC_SECRET")
    webhook_hmac_header: str = Field(default="X-Signature", env="WEBHOOK_HMAC_HEADER")
    webhook_hmac_prefix: str = Field(default="sha256=", env="WEBHOOK_HMAC_PREFIX")

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)

SETTINGS = Settings()
