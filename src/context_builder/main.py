from __future__ import annotations

import hmac
from contextlib import asynccontextmanager

import httpx
import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status

from .clients import TrivyOperatorClient, WazuhGatewayClient
from .config import Settings, get_settings
from .models import BuiltContext, ContextBuildRequest
from .service import build_context


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings: Settings = app.state.settings
    async with (
        httpx.AsyncClient(timeout=settings.context_builder_timeout_seconds) as wazuh_http,
        httpx.AsyncClient(
            timeout=settings.context_builder_timeout_seconds,
            verify=settings.trivy_tls_verify,
        ) as trivy_http,
    ):
        app.state.wazuh_gateway = WazuhGatewayClient(settings, wazuh_http)
        app.state.trivy_operator = (
            TrivyOperatorClient(settings, trivy_http)
            if settings.trivy_reports_url is not None
            else None
        )
        yield


def create_app(settings: Settings | None = None) -> FastAPI:
    app = FastAPI(
        title="Security Context Builder",
        version="0.1.0",
        description=(
            "Builds explainable security context from Wazuh gateway vulnerabilities "
            "and normalized Trivy findings."
        ),
        lifespan=lifespan,
    )
    app.state.settings = settings or get_settings()

    async def require_internal_token(
        request: Request,
        x_internal_token: str | None = Header(default=None, alias="X-Internal-Token"),
    ) -> None:
        expected = request.app.state.settings.context_builder_internal_token
        if not x_internal_token or not hmac.compare_digest(expected, x_internal_token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or invalid X-Internal-Token",
            )

    @app.get("/healthz", tags=["health"])
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post(
        "/v1/context/build",
        response_model=BuiltContext,
        tags=["context"],
        dependencies=[Depends(require_internal_token)],
    )
    async def build_context_route(
        payload: ContextBuildRequest,
        request: Request,
    ) -> BuiltContext:
        wazuh_rows: list[dict[str, object]] = []
        trivy_findings = []
        if payload.wazuh_agent_id:
            try:
                wazuh_rows = await request.app.state.wazuh_gateway.get_agent_vulnerabilities(
                    payload.wazuh_agent_id
                )
            except (httpx.HTTPError, ValueError) as exc:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Wazuh gateway request failed",
                ) from exc
        if payload.scope == "cluster":
            trivy_client = request.app.state.trivy_operator
            if trivy_client is None:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Trivy reports API is not configured",
                )
            try:
                trivy_findings = await trivy_client.list_findings()
            except (httpx.HTTPError, ValueError) as exc:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Trivy reports API request failed",
                ) from exc
        wazuh_agent_rows: dict[str, list[dict[str, object]]] = {}
        if payload.scope == "cluster":
            for agent_id in request.app.state.settings.cluster_agent_ids:
                try:
                    wazuh_agent_rows[agent_id] = (
                        await request.app.state.wazuh_gateway.get_agent_vulnerabilities(agent_id)
                    )
                except (httpx.HTTPError, ValueError) as exc:
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail="Wazuh gateway request failed",
                    ) from exc
        try:
            return build_context(payload, wazuh_rows, trivy_findings, wazuh_agent_rows)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Upstream returned invalid vulnerability data",
            ) from exc

    return app


def run() -> None:
    settings = get_settings()
    uvicorn.run(
        "context_builder.main:create_app",
        factory=True,
        host=settings.context_builder_host,
        port=settings.context_builder_port,
    )


if __name__ == "__main__":
    run()
