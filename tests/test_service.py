import pytest

from context_builder.models import (
    AssetContext,
    ContextBuildRequest,
    Criticality,
    Priority,
    Severity,
    TrivyFinding,
)
from context_builder.service import build_context


def test_builds_context_from_wazuh_and_trivy_and_escalates_corroboration() -> None:
    request = ContextBuildRequest(
        asset=AssetContext(
            asset_id="001",
            name="prod-api",
            criticality=Criticality.CRITICAL,
            internet_exposed=True,
        ),
        trivy_findings=[
            TrivyFinding(
                vulnerability_id="CVE-2026-1234",
                severity=Severity.HIGH,
            )
        ],
    )
    context = build_context(
        request,
        [
            {
                "cve": "CVE-2026-1234",
                "severity": "High",
                "agent_id": "001",
                "package": {"name": "openssl", "version": "3.0"},
            }
        ],
    )

    assert context.priority is Priority.CRITICAL
    assert context.finding_count == 2
    assert context.sources == ["wazuh", "trivy"]
    assert "cross_source_corroboration" in context.tags
    assert "critical_asset" in context.tags
    assert "internet_exposed" in context.tags
    assert {rule.id for rule in context.rules_applied} == {
        "baseline_highest_finding_severity",
        "critical_asset_escalation",
    }


def test_handles_empty_sources_as_info() -> None:
    request = ContextBuildRequest(asset=AssetContext(asset_id="agent-2"))

    context = build_context(request, [])

    assert context.priority is Priority.INFO
    assert context.finding_count == 0
    assert context.sources == []
    assert context.rules_applied[0].effect == "baseline"


def test_ignores_duplicate_source_finding_ids() -> None:
    request = ContextBuildRequest(
        asset=AssetContext(asset_id="agent-3"),
        trivy_findings=[
            TrivyFinding(
                finding_id="stable-1",
                vulnerability_id="CVE-2026-9999",
                severity=Severity.MEDIUM,
            ),
            TrivyFinding(
                finding_id="stable-1",
                vulnerability_id="CVE-2026-9999",
                severity=Severity.MEDIUM,
            ),
        ],
    )

    context = build_context(request, [])

    assert context.finding_count == 1


def test_rejects_wazuh_findings_for_a_different_agent() -> None:
    request = ContextBuildRequest(
        asset=AssetContext(asset_id="agent-4"),
        wazuh_agent_id="agent-4",
    )

    try:
        build_context(
            request,
            [{"cve": "CVE-2026-1", "severity": "High", "agent_id": "other-agent"}],
        )
    except ValueError as exc:
        assert "different agent" in str(exc)
    else:
        raise AssertionError("Expected mismatched Wazuh agent to be rejected")


def test_rejects_malformed_wazuh_finding() -> None:
    request = ContextBuildRequest(
        asset=AssetContext(asset_id="asset-5"),
        wazuh_agent_id="005",
    )

    try:
        build_context(request, [{"severity": "high"}])
    except ValueError as exc:
        assert "without a CVE" in str(exc)
    else:
        raise AssertionError("Expected malformed Wazuh finding to be rejected")


def test_cluster_scope_merges_node_agent_findings_and_corroborates() -> None:
    request = ContextBuildRequest(
        scope="cluster",
        trivy_findings=[
            TrivyFinding(vulnerability_id="CVE-2026-1234", severity=Severity.MEDIUM),
            TrivyFinding(vulnerability_id="CVE-2026-0001", severity=Severity.LOW),
        ],
    )
    context = build_context(
        request,
        [],
        wazuh_agent_rows={
            "001": [
                {
                    "cve": "CVE-2026-1234",
                    "severity": "Medium",
                    "agent_id": "001",
                    "agent_name": "node-kube-001",
                    "package": {"name": "openssl", "version": "3.0"},
                }
            ],
            "002": [],
        },
    )

    wazuh = [f for f in context.findings if f.source == "wazuh"]
    assert [(f.target, f.finding_id) for f in wazuh] == [
        ("node-kube-001", "wazuh:001:CVE-2026-1234:openssl:3.0")
    ]
    assert context.sources == ["wazuh", "trivy"]
    assert "cross_source_corroboration" in context.tags
    assert context.priority is Priority.HIGH


def test_cluster_scope_rejects_node_findings_for_a_different_agent() -> None:
    request = ContextBuildRequest(scope="cluster")
    with pytest.raises(ValueError, match="different agent"):
        build_context(
            request,
            [],
            wazuh_agent_rows={
                "001": [{"cve": "CVE-1", "severity": "High", "agent_id": "002"}]
            },
        )
