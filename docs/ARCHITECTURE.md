# Security Context Builder – Architecture

Diagrams use [Mermaid](https://mermaid.js.org), which GitHub renders natively.
For setup and API usage see [USAGE.md](USAGE.md).

## 1. System context

```mermaid
flowchart LR
    client["Internal client<br/>(analyst tooling / scripts)"]

    subgraph cb["Context Builder  :8090"]
        api["FastAPI service"]
    end

    subgraph wazuh["Wazuh VM"]
        gw["Wazuh VM gateway<br/>/v1/agents<br/>/v1/agents/{id}/vulnerabilities"]
        mgr[("Wazuh manager<br/>and indexer")]
        gw --> mgr
    end

    subgraph k8s["Kubernetes cluster"]
        kapi["Kubernetes API server<br/>vulnerabilityreports"]
        trivy["Trivy Operator"]
        trivy -->|writes VulnerabilityReports| kapi
    end

    ollama["Ollama (local)<br/>qwen2.5:3b<br/>optional"]

    client -->|"POST /v1/context/build<br/>X-Internal-Token"| api
    api -->|"HTTP + X-Internal-Token"| gw
    api -->|"HTTPS + SA bearer token<br/>CA-verified"| kapi
    api -.->|"/api/chat (if enabled)"| ollama
```

## 2. Application components

```mermaid
flowchart TB
    subgraph pkg["context_builder package"]
        main["main.py<br/>create_app, lifespan, routes<br/>/healthz, /v1/context/build<br/>X-Internal-Token check<br/>upstream error mapping to 502/503"]
        config["config.py<br/>Settings (pydantic-settings)<br/>.env and environment"]
        models["models.py<br/>ContextBuildRequest, SecurityFinding,<br/>WazuhAgent, PriorityRule,<br/>TriageAssessment, BuiltContext"]
        service["service.py<br/>build_context<br/>normalize Wazuh rows, merge findings,<br/>apply priority rules, tags,<br/>analyst summary"]

        subgraph clients["clients.py (async httpx)"]
            wc["WazuhGatewayClient<br/>list_agents<br/>get_agent_vulnerabilities"]
            tc["TrivyOperatorClient<br/>list_findings<br/>pagination via continue tokens<br/>report normalization"]
            oc["OllamaTriageClient<br/>assess<br/>evidence builder + JSON validation"]
        end
    end

    main --> config
    main --> models
    main --> service
    main --> wc
    main --> tc
    main -.->|"if LLM_TRIAGE_ENABLED"| oc
    service --> models
    wc --> models
    tc --> models
    oc --> models

    wc --> gw["Wazuh gateway"]
    tc --> kapi["Kubernetes API"]
    oc --> ol["Ollama"]
```

Notes:

- Each client gets its own lifespan-managed `httpx.AsyncClient` created in
  `main.py`, so Trivy TLS/CA settings and the long LLM timeout do not affect
  the Wazuh client. The Trivy client is only created when
  `TRIVY_REPORTS_URL` is set, and the LLM client only when
  `LLM_TRIAGE_ENABLED=true`.
- `service.py` is pure and synchronous: it takes already-fetched data and
  returns a `BuiltContext`, so it is unit-testable without network access.

## 3. Request flow

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant M as main.py (API)
    participant W as WazuhGatewayClient
    participant T as TrivyOperatorClient
    participant S as service.build_context
    participant O as OllamaTriageClient

    C->>M: POST /v1/context/build (X-Internal-Token)
    M->>M: Validate token and request model

    alt scope = asset
        opt wazuh_agent_id supplied
            M->>W: get_agent_vulnerabilities(agent_id)
            W-->>M: Wazuh rows
        end
        Note over M: Trivy findings come from the request body
    else scope = cluster
        M->>T: list_findings()
        T-->>M: Normalized Trivy findings (all pages)
        M->>W: list_agents()
        W-->>M: Agent inventory
        loop each selected agent (CLUSTER_WAZUH_AGENT_IDS or all active)
            M->>W: get_agent_vulnerabilities(id)
            W-->>M: Wazuh rows
        end
    end

    M->>S: build_context(payload, wazuh rows, trivy findings, agents)
    S-->>M: BuiltContext (priority, rules_applied, tags, findings)

    opt LLM triage enabled
        M->>O: assess(context)
        O-->>M: TriageAssessment
    end

    M-->>C: 200 BuiltContext
    Note over M,C: Any upstream failure returns 502, or 503 if Trivy is not configured
```

## 4. Priority pipeline

```mermaid
flowchart LR
    f["Merged findings<br/>(Wazuh + Trivy)"] --> b["Baseline:<br/>highest severity"]
    b --> r1{"Critical asset?"}
    r1 -->|"medium/high: +1 level"| r2{"Internet-exposed?"}
    r1 -->|no| r2
    r2 -->|"high: +1 level"| r3{"Same CVE in<br/>Wazuh and Trivy?"}
    r2 -->|no| r3
    r3 -->|"medium/high: +1 level"| cap["Cap at critical"]
    r3 -->|no| cap
    cap --> out["priority + rules_applied + tags"]
    out -.->|"advisory only, never changes priority"| llm["Optional LLM triage"]
```

## 5. Security boundaries

| Boundary | Control |
|---|---|
| Client → Context Builder | `X-Internal-Token`, constant-time comparison |
| Context Builder → Wazuh gateway | `X-Internal-Token` (gateway token) |
| Context Builder → Kubernetes API | Read-only service account (`get`, `list` on `vulnerabilityreports`), bearer token sent only over HTTPS, TLS verified against `TRIVY_API_CA_FILE` |
| Context Builder → Ollama | Local endpoint; only aggregate counts, agent inventory and up to 8 top findings per source (titles truncated) are sent |
| Secrets | `.env` and `secrets/` are git-ignored; keep mode 600 |
| Actions | None. The service only reads and reports; LLM output is advisory |
