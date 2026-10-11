from __future__ import annotations

from typing import Any

import httpx

from .config import Settings
from .models import PackageContext, Severity, TrivyFinding, TrivyReportResource


class WazuhGatewayClient:
    def __init__(self, settings: Settings, http_client: httpx.AsyncClient) -> None:
        self._settings = settings
        self._http_client = http_client

    async def get_agent_vulnerabilities(self, agent_id: str) -> list[dict[str, Any]]:
        url = (
            f"{str(self._settings.wazuh_gateway_url).rstrip('/')}"
            f"/v1/agents/{agent_id}/vulnerabilities"
        )
        response = await self._http_client.get(
            url,
            headers={"X-Internal-Token": self._settings.wazuh_gateway_internal_token},
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, list):
            raise ValueError("Wazuh gateway returned an unexpected vulnerability response")
        if not all(isinstance(item, dict) for item in payload):
            raise ValueError("Wazuh gateway returned a malformed vulnerability list")
        return payload


class TrivyOperatorClient:
    _PAGE_SIZE = 200
    _MAX_PAGES = 100
    _LABEL_PREFIX = "trivy-operator."

    def __init__(self, settings: Settings, http_client: httpx.AsyncClient) -> None:
        if settings.trivy_reports_url is None:
            raise ValueError("TRIVY_REPORTS_URL is required for cluster context")
        if (
            settings.trivy_api_bearer_token
            and settings.trivy_reports_url.scheme != "https"
        ):
            raise ValueError("TRIVY_REPORTS_URL must use HTTPS when a bearer token is configured")
        self._url = str(settings.trivy_reports_url)
        self._http_client = http_client
        self._headers = (
            {"Authorization": f"Bearer {settings.trivy_api_bearer_token}"}
            if settings.trivy_api_bearer_token
            else {}
        )

    async def list_findings(self) -> list[TrivyFinding]:
        findings: list[TrivyFinding] = []
        continuation: str | None = None
        seen_continuations: set[str] = set()

        for _ in range(self._MAX_PAGES):
            params: dict[str, str | int] = {"limit": self._PAGE_SIZE}
            if continuation:
                params["continue"] = continuation
            response = await self._http_client.get(
                self._url,
                params=params,
                headers=self._headers,
            )
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError("Trivy API returned an unexpected list response")
            items = payload.get("items")
            metadata = payload.get("metadata")
            if not isinstance(items, list) or not isinstance(metadata, dict):
                raise ValueError("Trivy API returned a malformed Kubernetes list response")
            for item in items:
                if not isinstance(item, dict):
                    raise ValueError("Trivy API returned a malformed vulnerability report")
                findings.extend(self._normalize_report(item))

            next_continuation = metadata.get("continue", "")
            if not isinstance(next_continuation, str):
                raise ValueError("Trivy API returned an invalid continuation token")
            if not next_continuation:
                return findings
            if next_continuation in seen_continuations:
                raise ValueError("Trivy API repeated a continuation token")
            seen_continuations.add(next_continuation)
            continuation = next_continuation

        raise ValueError("Trivy API pagination exceeded the configured page limit")

    @classmethod
    def _normalize_report(cls, report: dict[str, Any]) -> list[TrivyFinding]:
        metadata = report.get("metadata")
        report_data = report.get("report")
        if not isinstance(metadata, dict) or not isinstance(report_data, dict):
            raise ValueError("Trivy API returned a report without metadata or report data")
        report_name = metadata.get("name")
        if not isinstance(report_name, str) or not report_name:
            raise ValueError("Trivy API returned a report without a metadata name")

        labels = metadata.get("labels") or {}
        if not isinstance(labels, dict):
            raise ValueError("Trivy API returned malformed report labels")
        owner_references = metadata.get("ownerReferences") or []
        if not isinstance(owner_references, list):
            raise ValueError("Trivy API returned malformed report owner references")
        owner = next(
            (
                reference
                for reference in owner_references
                if isinstance(reference, dict) and reference.get("kind") and reference.get("name")
            ),
            {},
        )
        namespace = _string_or_none(metadata.get("namespace"))
        resource = TrivyReportResource(
            namespace=namespace,
            report_name=report_name,
            resource_name=_string_or_none(
                labels.get(f"{cls._LABEL_PREFIX}resource.name") or owner.get("name")
            ),
            resource_kind=_string_or_none(
                labels.get(f"{cls._LABEL_PREFIX}resource.kind") or owner.get("kind")
            ),
            container_name=_string_or_none(labels.get(f"{cls._LABEL_PREFIX}container.name")),
        )

        vulnerabilities = report_data.get("vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            raise ValueError("Trivy API returned malformed vulnerabilities")
        findings: list[TrivyFinding] = []
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise ValueError("Trivy API returned a malformed vulnerability")
            vulnerability_id = vulnerability.get("vulnerabilityID")
            severity_value = vulnerability.get("severity")
            if not isinstance(vulnerability_id, str) or not vulnerability_id:
                raise ValueError("Trivy API returned a vulnerability without an ID")
            if not isinstance(severity_value, str) or not severity_value:
                raise ValueError("Trivy API returned a vulnerability without severity")

            package_name = vulnerability.get("resource")
            package = (
                PackageContext(
                    name=package_name,
                    version=_string_or_none(vulnerability.get("installedVersion")),
                    fixed_version=_string_or_none(vulnerability.get("fixedVersion")),
                )
                if isinstance(package_name, str) and package_name
                else None
            )
            target = _string_or_none(vulnerability.get("target"))
            if target is None:
                target = resource.container_name
            cvss = vulnerability.get("score")
            if not isinstance(cvss, (int, float)) or isinstance(cvss, bool) or not 0 <= cvss <= 10:
                cvss = None
            findings.append(
                TrivyFinding(
                    finding_id=(
                        f"trivy:{namespace or 'cluster'}:{report_name}:"
                        f"{vulnerability_id}:{package_name or 'unknown'}:"
                        f"{vulnerability.get('installedVersion') or 'unknown'}"
                    ),
                    vulnerability_id=vulnerability_id,
                    severity=_normalize_trivy_severity(severity_value),
                    title=_string_or_none(vulnerability.get("title")),
                    description=_string_or_none(vulnerability.get("description")),
                    target=target,
                    package=package,
                    cvss=float(cvss) if cvss is not None else None,
                    resource=resource,
                )
            )
        return findings


def _string_or_none(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _normalize_trivy_severity(value: str) -> Severity:
    normalized = value.strip().lower()
    if normalized in {"unknown", "none"}:
        return Severity.INFO
    try:
        return Severity(normalized)
    except ValueError as exc:
        raise ValueError(f"Trivy API returned unsupported severity: {value!r}") from exc
