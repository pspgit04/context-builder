from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from uuid import uuid4

from .models import (
    AssetContext,
    BuiltContext,
    ContextBuildRequest,
    Criticality,
    PackageContext,
    Priority,
    PriorityRule,
    SecurityFinding,
    Severity,
    TrivyFinding,
)

_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
_RANK_PRIORITY = {
    0: Priority.INFO,
    1: Priority.LOW,
    2: Priority.MEDIUM,
    3: Priority.HIGH,
    4: Priority.CRITICAL,
}


def _normalized_severity(value: object) -> Severity:
    if isinstance(value, Severity):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        try:
            return Severity(normalized)
        except ValueError:
            pass
        numeric = {"0": Severity.LOW, "1": Severity.MEDIUM, "2": Severity.HIGH, "3": Severity.CRITICAL}
        if normalized in numeric:
            return numeric[normalized]
    if isinstance(value, int) and value in (0, 1, 2, 3):
        return (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)[value]
    raise ValueError(f"Wazuh response included an unsupported severity: {value!r}")


def _wazuh_findings(
    rows: list[dict[str, object]], asset: AssetContext, expected_agent_id: str | None
) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    for row in rows:
        cve = row.get("cve") or row.get("id")
        if not isinstance(cve, str) or not cve:
            raise ValueError("Wazuh response included a finding without a CVE")
        package_data = row.get("package")
        package: PackageContext | None = None
        if isinstance(package_data, dict):
            package_name = package_data.get("name")
            if not isinstance(package_name, str) or not package_name:
                raise ValueError("Wazuh response included a package without a name")
            package = PackageContext(
                name=package_name,
                version=_optional_string(package_data.get("version")),
            )
        elif package_data is not None:
            raise ValueError("Wazuh response included a malformed package")
        agent_id = row.get("agent_id")
        if (
            expected_agent_id is not None
            and agent_id is not None
            and str(agent_id) != expected_agent_id
        ):
            raise ValueError("Wazuh response included a finding for a different agent")
        package_version = package.version if package else "unknown"
        findings.append(
            SecurityFinding(
                source="wazuh",
                finding_id=(
                    f"wazuh:{expected_agent_id or asset.asset_id}:{cve}:"
                    f"{package.name if package else 'unknown'}:{package_version}"
                ),
                severity=_normalized_severity(row.get("severity")),
                title=_optional_string(row.get("title")),
                description=_optional_string(row.get("rationale")),
                cve=cve,
                package=package,
                cvss=_optional_float(row.get("cvss")),
            )
        )
    return findings


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _optional_float(value: object) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value <= 10:
        return float(value)
    return None


def _escalate_priority(priority: Priority) -> Priority:
    rank = _SEVERITY_RANK[Severity(priority.value)]
    return _RANK_PRIORITY[min(rank + 1, 4)]


def build_context(
    request: ContextBuildRequest,
    wazuh_rows: list[dict[str, object]],
    trivy_findings: list[TrivyFinding] | None = None,
) -> BuiltContext:
    findings = (
        _wazuh_findings(wazuh_rows, request.asset, request.wazuh_agent_id)
        if request.asset is not None
        else []
    )
    request_trivy_findings = [*request.trivy_findings, *(trivy_findings or [])]
    findings.extend(
        SecurityFinding(
            source="trivy",
            finding_id=(
                finding.finding_id
                or f"trivy:{request.asset.asset_id if request.asset else 'cluster'}:"
                f"{finding.vulnerability_id}:"
                f"{finding.package.name if finding.package else 'unknown'}"
            ),
            severity=finding.severity,
            title=finding.title,
            description=finding.description,
            target=finding.target,
            cve=finding.vulnerability_id,
            package=finding.package,
            cvss=finding.cvss,
            detected_at=finding.detected_at,
            resource=finding.resource,
        )
        for finding in request_trivy_findings
    )

    findings = list({(finding.source, finding.finding_id): finding for finding in findings}.values())
    severity = max(
        (finding.severity for finding in findings),
        key=_SEVERITY_RANK.__getitem__,
        default=Severity.INFO,
    )
    priority = _RANK_PRIORITY[_SEVERITY_RANK[severity]]
    rules: list[PriorityRule] = [
        PriorityRule(
            id="baseline_highest_finding_severity",
            reason=f"Baseline priority follows the highest finding severity: {severity.value}.",
            effect="baseline",
        )
    ]
    tags: set[str] = set()
    if (
        request.asset is not None
        and request.asset.criticality is Criticality.CRITICAL
        and priority in (
        Priority.MEDIUM,
        Priority.HIGH,
        )
    ):
        priority = _escalate_priority(priority)
        tags.add("critical_asset")
        rules.append(
            PriorityRule(
                id="critical_asset_escalation",
                reason="Finding priority was raised one level because the asset is critical.",
                effect="elevated",
            )
        )
    if (
        request.asset is not None
        and request.asset.internet_exposed
        and priority in (Priority.HIGH,)
    ):
        priority = _escalate_priority(priority)
        tags.add("internet_exposed")
        rules.append(
            PriorityRule(
                id="internet_exposure_escalation",
                reason="High-priority findings on an internet-exposed asset are escalated.",
                effect="elevated",
            )
        )

    cves_by_source: dict[str, set[str]] = {"wazuh": set(), "trivy": set()}
    for finding in findings:
        if finding.cve:
            cves_by_source[finding.source].add(finding.cve.upper())
    shared_cves = (
        cves_by_source["wazuh"] & cves_by_source["trivy"]
        if request.scope == "asset"
        else set()
    )
    if shared_cves:
        tags.add("cross_source_corroboration")
        if priority in (Priority.MEDIUM, Priority.HIGH):
            priority = _escalate_priority(priority)
            rules.append(
                PriorityRule(
                    id="cross_source_corroboration_escalation",
                    reason=(
                        "Wazuh and Trivy independently report the same vulnerability: "
                        f"{', '.join(sorted(shared_cves))}."
                    ),
                    effect="elevated",
                )
            )

    if request.asset is not None:
        if request.asset.criticality is Criticality.CRITICAL:
            tags.add("critical_asset")
        elif request.asset.criticality is Criticality.HIGH:
            tags.add("high_criticality_asset")
        if request.asset.internet_exposed:
            tags.add("internet_exposed")

    counts = Counter(finding.source for finding in findings)
    sources = [source for source in ("wazuh", "trivy") if counts[source]]
    context_subject = (
        request.asset.name or request.asset.asset_id if request.asset else "the cluster"
    )
    summary = (
        f"{len(findings)} vulnerability finding(s) across {len(sources)} source(s) "
        f"for {context_subject}; priority {priority.value}."
    )

    return BuiltContext(
        context_id=uuid4(),
        generated_at=datetime.now(UTC),
        scope=request.scope,
        asset=request.asset,
        priority=priority,
        rules_applied=rules,
        tags=sorted(tags),
        findings=findings,
        finding_count=len(findings),
        sources=sources,
        analyst_summary=summary,
    )
