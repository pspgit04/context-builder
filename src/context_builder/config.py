from functools import lru_cache
from pathlib import Path

from pydantic import Field, HttpUrl, model_validator
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
    trivy_api_bearer_token_file: Path | None = Field(
        default=None,
        description="File containing a service-account token; used when no token is set",
    )
    trivy_api_verify_tls: bool = True
    trivy_api_ca_file: Path | None = Field(
        default=None,
        description="CA bundle used to verify the Kubernetes API server certificate",
    )
    cluster_wazuh_agent_ids: str = Field(
        default="",
        description="Comma-separated Wazuh agent IDs of the cluster nodes, used for cluster scope",
    )
    context_builder_host: str = "0.0.0.0"
    context_builder_port: int = 8090
    context_builder_timeout_seconds: float = 10.0


    @model_validator(mode="after")
    def _load_token_file(self) -> "Settings":
        if not self.trivy_api_bearer_token and self.trivy_api_bearer_token_file:
            token = self.trivy_api_bearer_token_file.read_text(encoding="utf-8").strip()
            if not token:
                raise ValueError("TRIVY_API_BEARER_TOKEN_FILE is empty")
            self.trivy_api_bearer_token = token
        return self

    @property
    def cluster_agent_ids(self) -> list[str]:
        ids = [part.strip() for part in self.cluster_wazuh_agent_ids.split(",")]
        return list(dict.fromkeys(i for i in ids if i))

    @property
    def trivy_tls_verify(self) -> bool | str:
        if not self.trivy_api_verify_tls:
            return False
        return str(self.trivy_api_ca_file) if self.trivy_api_ca_file else True


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
