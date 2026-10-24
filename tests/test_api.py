import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from context_builder.config import Settings
from context_builder.main import create_app


@pytest.fixture
def settings() -> Settings:
    return Settings(
        _env_file=None,
        wazuh_gateway_url="https://gateway.test",
        wazuh_gateway_internal_token="wazuh-secret",
        context_builder_internal_token="builder-secret",
        trivy_reports_url=None,
    )


def test_build_route_fetches_wazuh_and_accepts_normalized_trivy(settings: Settings) -> None:
    app = create_app(settings)
    with respx.mock(assert_all_called=True) as mock:
        route = mock.get(
            "https://gateway.test/v1/agents/001/vulnerabilities",
            headers={"X-Internal-Token": "wazuh-secret"},
        ).respond(
            200,
            json=[
                {
                    "cve": "CVE-2026-1234",
                    "severity": "high",
                    "agent_id": "001",
                    "package": {"name": "openssl", "version": "3.0"},
                }
            ],
        )
        with TestClient(app) as client:
            response = client.post(
                "/v1/context/build",
                headers={"X-Internal-Token": "builder-secret"},
                json={
                    "asset": {"asset_id": "001", "name": "prod-api"},
                    "wazuh_agent_id": "001",
                    "trivy_findings": [
                        {"vulnerability_id": "CVE-2026-1234", "severity": "high"}
                    ],
                },
            )

    assert route.called
    assert response.status_code == 200
    assert response.json()["finding_count"] == 2
    assert response.json()["findings"][0]["agent_id"] == "001"
    assert response.json()["priority"] == "critical"
    assert "cross_source_corroboration" in response.json()["tags"]


def test_build_route_requires_its_internal_token(settings: Settings) -> None:
    with TestClient(create_app(settings)) as client:
        response = client.post(
            "/v1/context/build",
            json={"asset": {"asset_id": "001"}},
        )

    assert response.status_code == 401


def test_wazuh_upstream_failure_returns_gateway_error(settings: Settings) -> None:
    app = create_app(settings)
    with respx.mock(assert_all_called=True) as mock:
        mock.get("https://gateway.test/v1/agents/001/vulnerabilities").respond(503)
        with TestClient(app) as client:
            response = client.post(
                "/v1/context/build",
                headers={"X-Internal-Token": "builder-secret"},
                json={"asset": {"asset_id": "001"}, "wazuh_agent_id": "001"},
            )

    assert response.status_code == 502
    assert response.json()["detail"] == "Wazuh gateway request failed"


def test_build_route_accepts_asset_id_distinct_from_wazuh_agent_id(settings: Settings) -> None:
    app = create_app(settings)
    with respx.mock(assert_all_called=True) as mock:
        mock.get("https://gateway.test/v1/agents/001/vulnerabilities").respond(
            200,
            json=[
                {
                    "cve": "CVE-2026-1234",
                    "severity": "high",
                    "agent_id": "001",
                }
            ],
        )
        with TestClient(app) as client:
            response = client.post(
                "/v1/context/build",
                headers={"X-Internal-Token": "builder-secret"},
                json={
                    "asset": {"asset_id": "asset-prod-api"},
                    "wazuh_agent_id": "001",
                },
            )

    assert response.status_code == 200
    assert response.json()["finding_count"] == 1


def test_cluster_context_pages_trivy_reports_and_preserves_resource_metadata() -> None:
    url = (
        "https://trivy.test/apis/aquasecurity.github.io/v1alpha1/"
        "vulnerabilityreports"
    )
    settings = Settings(
        wazuh_gateway_url="https://gateway.test",
        wazuh_gateway_internal_token="wazuh-secret",
        context_builder_internal_token="builder-secret",
        trivy_reports_url=url,
        trivy_api_bearer_token="trivy-secret",
    )
    first_report = {
        "metadata": {
            "name": "deployment-a-container",
            "namespace": "production",
            "labels": {
                "trivy-operator.resource.name": "deployment-a",
                "trivy-operator.resource.kind": "ReplicaSet",
                "trivy-operator.container.name": "api",
            },
        },
        "report": {
            "vulnerabilities": [
                {
                    "vulnerabilityID": "CVE-2026-2468",
                    "severity": "CRITICAL",
                    "resource": "openssl",
                    "installedVersion": "3.0.0",
                    "fixedVersion": "3.0.1",
                    "title": "Example critical vulnerability",
                    "score": 9.8,
                }
            ]
        },
    }
    second_report = {
        "metadata": {
            "name": "pod-b-container",
            "namespace": "staging",
            "ownerReferences": [{"kind": "Pod", "name": "pod-b"}],
        },
        "report": {
            "vulnerabilities": [
                {
                    "vulnerabilityID": "CVE-2026-9753",
                    "severity": "UNKNOWN",
                    "resource": "libfoo",
                    "installedVersion": "1.0",
                }
            ]
        },
    }
    with respx.mock(assert_all_called=True) as mock:
        mock.get(
            "https://gateway.test/v1/agents",
            params={"status": "active", "limit": 2000},
            headers={"X-Internal-Token": "wazuh-secret"},
        ).respond(200, json={"total": 0, "items": []})
        route = mock.get(
            url,
            headers={"Authorization": "Bearer trivy-secret"},
        ).mock(
            side_effect=[
                httpx.Response(
                    200,
                    json={"metadata": {"continue": "page-2"}, "items": [first_report]},
                ),
                httpx.Response(200, json={"metadata": {"continue": ""}, "items": [second_report]}),
            ]
        )
        with TestClient(create_app(settings)) as client:
            response = client.post(
                "/v1/context/build",
                headers={"X-Internal-Token": "builder-secret"},
                json={"scope": "cluster"},
            )

    assert route.call_count == 2
    assert response.status_code == 200
    body = response.json()
    assert body["scope"] == "cluster"
    assert body["asset"] is None
    assert body["finding_count"] == 2
    assert body["priority"] == "critical"
    assert body["wazuh_agents"] == []
    assert body["findings"][0]["resource"] == {
        "namespace": "production",
        "report_name": "deployment-a-container",
        "resource_name": "deployment-a",
        "resource_kind": "ReplicaSet",
        "container_name": "api",
    }
    assert body["findings"][0]["package"] == {
        "name": "openssl",
        "version": "3.0.0",
        "fixed_version": "3.0.1",
    }
    assert body["findings"][1]["severity"] == "info"


def test_cluster_scope_includes_configured_wazuh_node_agents() -> None:
    settings = Settings(
        _env_file=None,
        wazuh_gateway_url="https://gateway.test",
        wazuh_gateway_internal_token="wazuh-secret",
        context_builder_internal_token="builder-secret",
        trivy_reports_url="https://kube.test/apis/aquasecurity.github.io/v1alpha1/vulnerabilityreports",
        cluster_wazuh_agent_ids="001, 002,001",
    )
    report = {
        "metadata": {"name": "r", "namespace": "ns"},
        "report": {
            "vulnerabilities": [
                {"vulnerabilityID": "CVE-2026-1", "severity": "MEDIUM", "resource": "zlib"}
            ]
        },
    }
    with respx.mock(assert_all_called=True) as mock:
        mock.get("https://kube.test/apis/aquasecurity.github.io/v1alpha1/vulnerabilityreports").respond(
            200, json={"metadata": {"continue": ""}, "items": [report]}
        )
        mock.get(
            "https://gateway.test/v1/agents",
            params={"status": "active", "limit": 2000},
            headers={"X-Internal-Token": "wazuh-secret"},
        ).respond(
            200,
            json={
                "total": 1,
                "items": [
                    {
                        "id": "001",
                        "name": "node-kube-001",
                        "ip": "10.10.4.7",
                        "status": "active",
                        "vulnerability_counts": {"medium": 1},
                    }
                ],
            },
        )
        node1 = mock.get(
            "https://gateway.test/v1/agents/001/vulnerabilities",
            headers={"X-Internal-Token": "wazuh-secret"},
        ).respond(
            200,
            json=[
                {
                    "cve": "CVE-2026-1",
                    "severity": "medium",
                    "agent_id": "001",
                    "agent_name": "node-kube-001",
                    "package": {"name": "zlib", "version": "1.2"},
                }
            ],
        )
        node2 = mock.get("https://gateway.test/v1/agents/002/vulnerabilities").respond(200, json=[])
        with TestClient(create_app(settings)) as client:
            response = client.post(
                "/v1/context/build",
                headers={"X-Internal-Token": "builder-secret"},
                json={"scope": "cluster"},
            )

    assert node1.call_count == 1 and node2.call_count == 1
    body = response.json()
    assert response.status_code == 200
    assert body["sources"] == ["wazuh", "trivy"]
    assert body["wazuh_agents"][0]["id"] == "001"
    assert body["wazuh_agents"][0]["vulnerability_counts"]["medium"] == 1
    wazuh_finding = next(item for item in body["findings"] if item["source"] == "wazuh")
    assert wazuh_finding["agent_id"] == "001"
    assert "cross_source_corroboration" in body["tags"]
    assert body["priority"] == "high"


def test_cluster_context_fetches_vulnerabilities_for_active_agents_by_default() -> None:
    settings = Settings(
        _env_file=None,
        wazuh_gateway_url="https://gateway.test",
        wazuh_gateway_internal_token="wazuh-secret",
        context_builder_internal_token="builder-secret",
        trivy_reports_url="https://kube.test/apis/aquasecurity.github.io/v1alpha1/vulnerabilityreports",
    )
    with respx.mock(assert_all_called=True) as mock:
        mock.get("https://kube.test/apis/aquasecurity.github.io/v1alpha1/vulnerabilityreports").respond(
            200, json={"metadata": {"continue": ""}, "items": []}
        )
        mock.get(
            "https://gateway.test/v1/agents",
            params={"status": "active", "limit": 2000},
            headers={"X-Internal-Token": "wazuh-secret"},
        ).respond(
            200,
            json={
                "total": 1,
                "items": [{"id": "001", "name": "node-kube-001", "status": "active"}],
            },
        )
        mock.get(
            "https://gateway.test/v1/agents/001/vulnerabilities",
            headers={"X-Internal-Token": "wazuh-secret"},
        ).respond(
            200,
            json=[
                {
                    "cve": "CVE-2026-1234",
                    "severity": "high",
                    "agent_id": "001",
                    "agent_name": "node-kube-001",
                }
            ],
        )
        with TestClient(create_app(settings)) as client:
            response = client.post(
                "/v1/context/build",
                headers={"X-Internal-Token": "builder-secret"},
                json={"scope": "cluster"},
            )

    assert response.status_code == 200
    body = response.json()
    assert body["sources"] == ["wazuh"]
    assert body["wazuh_agents"][0]["id"] == "001"
    assert body["findings"][0]["agent_id"] == "001"


def test_cluster_scope_wazuh_failure_returns_gateway_error() -> None:
    settings = Settings(
        _env_file=None,
        wazuh_gateway_url="https://gateway.test",
        wazuh_gateway_internal_token="wazuh-secret",
        context_builder_internal_token="builder-secret",
        trivy_reports_url="https://kube.test/apis/aquasecurity.github.io/v1alpha1/vulnerabilityreports",
        cluster_wazuh_agent_ids="001",
    )
    with respx.mock() as mock:
        mock.get("https://kube.test/apis/aquasecurity.github.io/v1alpha1/vulnerabilityreports").respond(
            200, json={"metadata": {"continue": ""}, "items": []}
        )
        mock.get(
            "https://gateway.test/v1/agents",
            params={"status": "active", "limit": 2000},
        ).respond(200, json={"total": 0, "items": []})
        mock.get("https://gateway.test/v1/agents/001/vulnerabilities").respond(503)
        with TestClient(create_app(settings)) as client:
            response = client.post(
                "/v1/context/build",
                headers={"X-Internal-Token": "builder-secret"},
                json={"scope": "cluster"},
            )

    assert response.status_code == 502


def test_cluster_scope_requires_configured_trivy_api(settings: Settings) -> None:
    with TestClient(create_app(settings)) as client:
        response = client.post(
            "/v1/context/build",
            headers={"X-Internal-Token": "builder-secret"},
            json={"scope": "cluster"},
        )

    assert response.status_code == 503
    assert response.json()["detail"] == "Trivy reports API is not configured"


def test_token_file_and_ca_file_settings(tmp_path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("file-token\n")
    ca_file = tmp_path / "ca.crt"
    settings = Settings(
        _env_file=None,
        wazuh_gateway_url="https://gateway.test",
        wazuh_gateway_internal_token="wazuh-secret",
        context_builder_internal_token="builder-secret",
        trivy_api_bearer_token_file=token_file,
        trivy_api_ca_file=ca_file,
    )

    assert settings.trivy_api_bearer_token == "file-token"
    assert settings.trivy_tls_verify == str(ca_file)


def test_empty_token_file_is_rejected(tmp_path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("\n")

    with pytest.raises(ValueError, match="TRIVY_API_BEARER_TOKEN_FILE is empty"):
        Settings(
            _env_file=None,
            wazuh_gateway_url="https://gateway.test",
            wazuh_gateway_internal_token="wazuh-secret",
            context_builder_internal_token="builder-secret",
            trivy_api_bearer_token_file=token_file,
        )


def test_cluster_bearer_token_requires_https() -> None:
    settings = Settings(
        _env_file=None,
        wazuh_gateway_url="https://gateway.test",
        wazuh_gateway_internal_token="wazuh-secret",
        context_builder_internal_token="builder-secret",
        trivy_reports_url=(
            "http://trivy.test/apis/aquasecurity.github.io/v1alpha1/"
            "vulnerabilityreports"
        ),
        trivy_api_bearer_token="trivy-secret",
    )

    with pytest.raises(ValueError, match="must use HTTPS"), TestClient(create_app(settings)):
        pass
