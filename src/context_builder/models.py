from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Priority(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Criticality(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class PackageContext(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    version: str | None = None
    fixed_version: str | None = None


class TrivyReportResource(BaseModel):
    namespace: str | None = None
    report_name: str
    resource_name: str | None = None
    resource_kind: str | None = None
    container_name: str | None = None


class AssetContext(BaseModel):
    asset_id: str = Field(min_length=1, max_length=256)
    name: str | None = None
    environment: str | None = None
    criticality: Criticality = Criticality.MEDIUM
    internet_exposed: bool = False
    owner: str | None = None


class TrivyFinding(BaseModel):
    """Normalized Trivy finding."""

    model_config = ConfigDict(extra="ignore")

    finding_id: str | None = None
    vulnerability_id: str = Field(min_length=1)
    severity: Severity
    title: str | None = None
    description: str | None = None
    target: str | None = None
    package: PackageContext | None = None
    cvss: float | None = Field(default=None, ge=0, le=10)
    detected_at: datetime | None = None
    resource: TrivyReportResource | None = None


class ContextBuildRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope: Literal["asset", "cluster"] = "asset"
    asset: AssetContext | None = None
    wazuh_agent_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9_.-]+$",
    )
    trivy_findings: list[TrivyFinding] = Field(default_factory=list, max_length=500)

    @model_validator(mode="after")
    def validate_scope(self) -> ContextBuildRequest:
        if self.scope == "asset" and self.asset is None:
            raise ValueError("asset is required when scope is 'asset'")
        if self.scope == "cluster" and (self.asset is not None or self.wazuh_agent_id is not None):
            raise ValueError("cluster scope cannot specify an asset or Wazuh agent")
        return self


class SecurityFinding(BaseModel):
    source: Literal["wazuh", "trivy"]
    finding_id: str
    kind: Literal["vulnerability"] = "vulnerability"
    severity: Severity
    title: str | None = None
    description: str | None = None
    target: str | None = None
    cve: str | None = None
    package: PackageContext | None = None
    cvss: float | None = Field(default=None, ge=0, le=10)
    detected_at: datetime | None = None
    resource: TrivyReportResource | None = None


class PriorityRule(BaseModel):
    id: str
    reason: str
    effect: Literal["baseline", "elevated"]


class BuiltContext(BaseModel):
    context_id: UUID
    generated_at: datetime
    scope: Literal["asset", "cluster"]
    asset: AssetContext | None = None
    priority: Priority
    rules_applied: list[PriorityRule]
    tags: list[str]
    findings: list[SecurityFinding]
    finding_count: int
    sources: list[Literal["wazuh", "trivy"]]
    analyst_summary: str

    @model_validator(mode="after")
    def finding_count_matches(self) -> BuiltContext:
        if self.finding_count != len(self.findings):
            raise ValueError("finding_count must match the number of findings")
        return self
