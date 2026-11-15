# Security Context Builder – Usage Guide

The Context Builder is an internal HTTP service that correlates vulnerability
data from **Wazuh** (via the Wazuh VM gateway) and **Trivy Operator**
(Kubernetes `VulnerabilityReport` objects) and returns one normalized,
explainable context object with a deterministic priority. It can optionally
add an advisory summary from a local Ollama model. It never triggers
remediation.

## 1. Prerequisites

- Python 3.11+ (developed on 3.14).
- Network access to the Wazuh gateway and, for cluster scope, the Kubernetes
  API server.
- Optional: [Ollama](https://ollama.com) with `qwen2.5:3b` for LLM triage.

## 2. Install

```bash
cd context-builder
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

If `python3 -m venv` fails because `ensurepip` is missing and you have no
sudo, create the venv without pip and bootstrap it:

```bash
python3 -m venv --without-pip .venv
curl -sS https://bootstrap.pypa.io/get-pip.py | .venv/bin/python
.venv/bin/pip install -e ".[dev]"
```

## 3. Configure

```bash
cp .env.example .env
chmod 600 .env
```

Settings are read from `.env` or environment variables (case-insensitive).

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `WAZUH_GATEWAY_URL` | yes | – | Base URL of the Wazuh VM gateway (must be reachable from this host) |
| `WAZUH_GATEWAY_INTERNAL_TOKEN` | yes | – | Sent to the gateway as `X-Internal-Token` |
| `CONTEXT_BUILDER_INTERNAL_TOKEN` | yes | – | Token clients must send to this service |
| `TRIVY_REPORTS_URL` | cluster scope | unset | Kubernetes API list endpoint for `vulnerabilityreports` |
| `TRIVY_API_BEARER_TOKEN` / `TRIVY_API_BEARER_TOKEN_FILE` | if API needs auth | unset | Service-account token (only sent over HTTPS) |
| `TRIVY_API_CA_FILE` | recommended | unset | Cluster CA bundle for TLS verification |
| `TRIVY_API_VERIFY_TLS` | no | `true` | Keep `true` in production |
| `CLUSTER_WAZUH_AGENT_IDS` | no | empty (all active agents) | Comma-separated agent IDs to restrict cluster Wazuh lookups |
| `CONTEXT_BUILDER_HOST` / `CONTEXT_BUILDER_PORT` | no | `0.0.0.0` / `8090` | Listen address |
| `CONTEXT_BUILDER_TIMEOUT_SECONDS` | no | `10.0` | Timeout for Wazuh/Trivy calls |
| `LLM_TRIAGE_ENABLED` | no | `false` | Enable Ollama triage |
| `LLM_TRIAGE_URL` | no | `http://127.0.0.1:11434/api/chat` | Ollama chat endpoint |
| `LLM_TRIAGE_MODEL` | no | `qwen2.5:3b` | Ollama model |
| `LLM_TRIAGE_TIMEOUT_SECONDS` | no | `300.0` | LLM request timeout |
| `LLM_TRIAGE_NUM_CTX` | no | `8192` | Ollama context window |

For the read-only Kubernetes service account and token/CA setup, see
[README.md](../README.md#read-only-service-account). Keep tokens and the CA
file in `secrets/` (mode 600); `.env` and `secrets/` are git-ignored.

## 4. Run

```bash
source .venv/bin/activate
context-builder          # listens on 0.0.0.0:8090 by default
```

Check it is up:

```bash
curl http://localhost:8090/healthz
# {"status":"ok"}
```

Interactive API docs are served at `http://localhost:8090/docs`.

## 5. API

### `POST /v1/context/build`

Header: `X-Internal-Token: <CONTEXT_BUILDER_INTERNAL_TOKEN>`

Two scopes are supported.

#### Asset scope (default)

Builds context for one asset. Provide normalized Trivy findings in the body
and, optionally, a `wazuh_agent_id` to pull that agent's vulnerabilities from
the gateway.

```bash
curl -s -X POST http://localhost:8090/v1/context/build \
  -H "X-Internal-Token: $CONTEXT_BUILDER_INTERNAL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "asset": {
      "asset_id": "prod-api-01",
      "name": "prod-api-01",
      "environment": "production",
      "criticality": "critical",
      "internet_exposed": true,
      "owner": "platform"
    },
    "wazuh_agent_id": "001",
    "trivy_findings": [
      {
        "finding_id": "scan-1:CVE-2026-1234:openssl",
        "vulnerability_id": "CVE-2026-1234",
        "severity": "high",
        "title": "openssl vulnerability",
        "target": "prod-api:latest",
        "package": {"name": "openssl", "version": "3.0.0", "fixed_version": "3.0.1"},
        "cvss": 8.2,
        "detected_at": "2026-10-11T14:00:00Z"
      }
    ]
  }'
```

Severities: `critical`, `high`, `medium`, `low`, `info`.
`wazuh_agent_id` and `trivy_findings` are optional.

#### Cluster scope

Pulls all Trivy Operator reports from the Kubernetes API plus Wazuh agent
inventory and vulnerabilities. Do **not** send `asset` or `wazuh_agent_id`.

```bash
curl -s -X POST http://localhost:8090/v1/context/build \
  -H "X-Internal-Token: $CONTEXT_BUILDER_INTERNAL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"scope": "cluster"}'
```

Requires `TRIVY_REPORTS_URL`. Wazuh vulnerabilities are fetched for every
active agent unless `CLUSTER_WAZUH_AGENT_IDS` is set.

### Response

| Field | Description |
|---|---|
| `context_id`, `generated_at` | Unique ID and timestamp |
| `scope` | `asset` or `cluster` (`asset` is `null` for cluster) |
| `asset` | Echo of the supplied asset |
| `wazuh_agents` | Cluster scope: agent identity, status, vulnerability counts |
| `priority` | `info`…`critical`, from the deterministic rules below |
| `rules_applied` | Each rule applied with its `id`, `reason`, and `effect` (`baseline`/`elevated`) |
| `tags` | e.g. criticality, exposure, `cross_source_corroboration` |
| `findings` | Normalized findings from both sources; Wazuh findings carry `agent_id`, Trivy findings carry namespace/report/workload/container in `resource` |
| `finding_count`, `sources` | Count and sources (`wazuh`, `trivy`) |
| `analyst_summary` | Deterministic text summary |
| `triage` | LLM assessment, or `null` when triage is disabled |

### Priority rules

1. Baseline = highest severity among findings.
2. Critical asset: medium/high raised one level.
3. Internet-exposed asset: high raised one level.
4. Same CVE in both Wazuh and Trivy: medium/high raised one level
   (`cross_source_corroboration`).

Priority is capped at `critical`. These are heuristics, not calibrated risk
scores, and never authorize response actions.

### Errors

| Status | Meaning |
|---|---|
| 401 | Missing or invalid `X-Internal-Token` |
| 422 | Invalid request (e.g. asset scope without `asset`, cluster scope with `asset`) |
| 502 | Wazuh gateway, Trivy API, or LLM request failed, or upstream returned malformed data. Cluster scope fails entirely if any selected Wazuh agent fails |
| 503 | Cluster scope requested but `TRIVY_REPORTS_URL` is not configured |

## 6. Optional LLM triage

```bash
ollama serve &                 # if not already running
ollama pull qwen2.5:3b
```

Set `LLM_TRIAGE_ENABLED=true` in `.env` and restart the service. The
response then includes:

```json
"triage": {
  "summary": "...",
  "key_observations": ["..."],
  "recommended_actions": ["..."],
  "supporting_finding_ids": ["scan-1:CVE-2026-1234:openssl"]
}
```

Notes:

- Only aggregate counts, the Wazuh agent inventory, and up to 8
  highest-severity findings per source (titles truncated to 120 characters)
  are sent to the Ollama endpoint.
- Triage is advisory. It never changes `priority` or triggers actions.
- On CPU-only hosts it is slow. A 3-finding request took about 180 s on 5
  cores with `qwen2.5:3b`, so keep `LLM_TRIAGE_TIMEOUT_SECONDS` generous and
  tune `LLM_TRIAGE_NUM_CTX`.
- Small models can misstate details (for example, describing a medium CVE as
  high). Always rely on `priority`, `rules_applied`, and `findings` as the
  source of truth.
- A failed LLM call currently returns `502` for the whole request.

## 7. Tests

```bash
source .venv/bin/activate
pytest -q
```

## 8. Troubleshooting

| Symptom | Check |
|---|---|
| 401 | `X-Internal-Token` matches `CONTEXT_BUILDER_INTERNAL_TOKEN` |
| 502 "Wazuh gateway request failed" | `WAZUH_GATEWAY_URL` is reachable from this host and the gateway token is correct |
| 502 "Trivy reports API request failed" | Token not expired (`kubectl create token` tokens expire), CA file correct, URL reachable |
| 503 on cluster scope | `TRIVY_REPORTS_URL` is set |
| 502 "LLM triage request failed" | Ollama is running, model is pulled, timeout is large enough |
| No Wazuh findings for Kubernetes nodes | Known gap: Wazuh cannot scan Ubuntu 25.10 nodes; see [README.md](../README.md#known-gaps) |
