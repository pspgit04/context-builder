# Security Context Builder

An internal service that assembles a normalized, explainable context object
from the Wazuh vulnerability gateway and normalized Trivy findings. Wazuh and
Trivy remain the detection/data sources; this service correlates findings and
applies deterministic priority rules. It does not call an LLM or trigger
remediation.

## Current integration boundary

- Wazuh is queried through the existing gateway endpoint
  `GET /v1/agents/{agent_id}/vulnerabilities`, using
  `X-Internal-Token`.
- The existing gateway currently exposes agent and vulnerability data, not
  Wazuh security alerts. This MVP therefore builds vulnerability context.
- Trivy cluster mode queries the configured Kubernetes API list endpoint for
  Trivy Operator `VulnerabilityReport` objects, follows Kubernetes
  continuation tokens, and preserves report namespace/workload/container
  metadata with each finding.
- Asset scope can still accept normalized Trivy findings in the request body.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
# Set both internal tokens and the reachable Wazuh gateway URL in .env.
context-builder
```

The service listens on port `8090` by default. Liveness is available at
`GET /healthz`; the internal API is protected by `X-Internal-Token`.

## Build context

`POST /v1/context/build`

```json
{
  "asset": {
    "asset_id": "001",
    "name": "prod-api-01",
    "environment": "production",
    "criticality": "critical",
    "internet_exposed": true,
    "owner": "platform"
  },
  "wazuh_agent_id": "001",
  "trivy_findings": [
    {
      "finding_id": "scan-42:CVE-2026-1234:openssl",
      "vulnerability_id": "CVE-2026-1234",
      "severity": "high",
      "title": "Example vulnerability",
      "description": "Normalized finding description",
      "target": "prod-api:latest",
      "package": {
        "name": "openssl",
        "version": "3.0.0",
        "fixed_version": "3.0.1"
      },
      "cvss": 8.2,
      "detected_at": "2026-10-11T14:00:00Z"
    }
  ]
}
```

Severity values are `critical`, `high`, `medium`, `low`, and `info`.
`wazuh_agent_id` is optional; omit it if no Wazuh lookup is needed.

For a cluster-wide Trivy context, do not include an `asset` or
`wazuh_agent_id`; set the scope to `cluster`:

```json
{
  "scope": "cluster"
}
```

The response has `scope: "cluster"` and `asset: null`. Every Trivy finding
includes its Kubernetes namespace, report name, and available workload and
container labels.

Set `CLUSTER_WAZUH_AGENT_IDS` (comma-separated, for example `001,002,003`) to the
Wazuh agent IDs of the cluster nodes. Cluster scope then also pulls each node
agent's vulnerabilities from the gateway; those findings carry the agent name as
their `target`. When Wazuh and Trivy report the same CVE, the context is tagged
`cross_source_corroboration` and its priority is raised one level (medium and
high only). With the setting empty, cluster scope is Trivy-only. If the gateway
fails for any listed agent, the request returns 502 rather than a partial result.

Configure `TRIVY_REPORTS_URL` to the Kubernetes API list endpoint. If the API
requires authentication, provide a service-account token using
`TRIVY_API_BEARER_TOKEN` or `TRIVY_API_BEARER_TOKEN_FILE`; bearer tokens are
only sent to HTTPS endpoints. TLS certificate verification is enabled by
default; set `TRIVY_API_CA_FILE` to the cluster CA bundle rather than disabling
verification in production.

### Read-only service account

Create the account on a machine with cluster access:

```bash
kubectl create namespace context-builder
kubectl create serviceaccount context-builder -n context-builder
kubectl create clusterrole trivy-reports-reader \
  --verb=get,list --resource=vulnerabilityreports.aquasecurity.github.io
kubectl create clusterrolebinding context-builder-trivy-reader \
  --clusterrole=trivy-reports-reader \
  --serviceaccount=context-builder:context-builder
kubectl create token context-builder -n context-builder --duration=8760h > trivy-token
kubectl config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' \
  | base64 -d > cluster-ca.crt
```

Copy both files to `secrets/` (mode 600) and point the `.env` settings at them.
Tokens from `kubectl create token` expire, so rotate before the duration ends.

## Initial priority rules

- Baseline priority is the highest severity among the findings.
- A critical asset raises medium/high priority by one level.
- An internet-exposed asset raises high priority by one level.
- A CVE independently present in both Wazuh and Trivy raises medium/high
  priority by one level.
- Priority is capped at critical. Every applied escalation is returned in
  `rules_applied`; applicable escalations are evaluated in the order above,
  and tags show criticality, exposure, and cross-source corroboration.
- Wazuh findings are rejected as an upstream error if they are malformed;
  unsupported severities are not silently treated as informational.

These are initial deterministic heuristics, not calibrated risk scores.
They affect prioritization only and never authorize response actions.

## Known gaps

- **Kubernetes node OS vulnerabilities are not covered.** The Wazuh agents on
  node-kube-001..003 are installed and reporting, but the nodes run Ubuntu 25.10
  (an interim release) and the Wazuh scanner logs
  `OS scan for platform 'ubuntu' on Agent '001' is not supported.` Wazuh
  therefore produces no findings for them, and `CLUSTER_WAZUH_AGENT_IDS` is left
  unset. Trivy still covers workloads. Revisit by moving the nodes to an
  Ubuntu LTS release, or by adding Trivy `rootfs` host scans per node.

## Tests

```bash
pytest -q
```
