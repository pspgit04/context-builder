from functools import lru_cache

from pydantic import Field, HttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    wazuh_gateway_url: HttpUrl = Field(..., description="Base URL of the Wazuh API gateway")
    wazuh_gateway_internal_token: str = Field(
        ..., description="Token used to call the Wazuh API gateway"
    )
    context_builder_internal_token: str = Field(
        ..., description="Token required by Context Builder clients"
    )
    trivy_reports_url: HttpUrl | None = Field(
        default=None,
        description="Kubernetes API list endpoint for Trivy VulnerabilityReport resources",
    )
    trivy_api_bearer_token: str | None = Field(
        default=None,
        description="Optional bearer token for the Kubernetes API",
    )
    trivy_api_verify_tls: bool = True
    context_builder_host: str = "0.0.0.0"
    context_builder_port: int = 8090
    context_builder_timeout_seconds: float = 10.0


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
