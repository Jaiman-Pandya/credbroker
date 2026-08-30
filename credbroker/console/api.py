"""HTTP routes for the operator console.

Dependencies come off ``request.app.state`` (settings, session_factory,
cipher, grant_cache, rate_limiter, invoke_service) exactly as wired by
:func:`credbroker.app.create_app`. All business logic lives in the grant and
invoke services; this layer only parses requests, delegates, maps broker
domain errors onto HTTP status codes, and serializes plain JSON dicts.

Auth: when ``settings.console_token`` is non-empty, every ``/console/api/*``
endpoint requires an ``X-Console-Token`` header equal to it (compared in
constant time). An empty token leaves the console open — dev only. The HTML
page itself is served unauthenticated: it is a static shell with no data;
everything it displays comes from the guarded API.

Security invariant, restated for this surface: responses never contain
encrypted token blobs, decrypted provider credentials, or JWT keys. The one
deliberate exception to grant-token secrecy is ``POST /console/api/grants``,
which returns the freshly signed grant token — the console plays the agent,
and a grant token is exactly what an agent is meant to hold.
"""

import hmac
import uuid
from datetime import datetime
from importlib import resources

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy import select

from credbroker.db.models import (
    AgentIdentity,
    ConnectedAccount,
    Grant,
    ToolCallAuditLog,
    ensure_aware,
    utcnow,
)
from credbroker.demo.seed import seed_demo
from credbroker.errors import (
    ConcurrencyLimitError,
    CredBrokerError,
    GrantExpiredError,
    GrantNotFoundError,
    GrantRevokedError,
    GrantScopeMismatchError,
    GrantTokenInvalidError,
    IdempotencyConflictError,
    NoConnectedAccountError,
    PolicyDeniedError,
    RateLimitedError,
    UnknownAgentError,
    UnknownToolError,
)
from credbroker.grants import service as grants_service
from credbroker.tools import TOOL_REGISTRY

# Domain error -> HTTP status. Exact classes only; anything else in the
# CredBrokerError hierarchy falls back to 400. Every message on these errors
# is safe to surface by construction (see credbroker.errors).
_ERROR_STATUS: dict[type[CredBrokerError], int] = {
    PolicyDeniedError: 403,
    GrantScopeMismatchError: 403,
    GrantRevokedError: 403,
    GrantExpiredError: 403,
    GrantTokenInvalidError: 403,
    RateLimitedError: 429,
    ConcurrencyLimitError: 429,
    UnknownAgentError: 404,
    UnknownToolError: 404,
    GrantNotFoundError: 404,
    NoConnectedAccountError: 404,
    IdempotencyConflictError: 409,
}


def _http_error(exc: CredBrokerError) -> HTTPException:
    return HTTPException(status_code=_ERROR_STATUS.get(type(exc), 400), detail=str(exc))


def require_console_auth(
    request: Request, x_console_token: str | None = Header(default=None)
) -> None:
    """Enforce the shared console token when one is configured.

    An empty ``console_token`` setting leaves the console open (dev only).
    The comparison is constant-time so the token cannot be recovered
    byte-by-byte through timing.
    """
    expected = request.app.state.settings.console_token
    if not expected:
        return
    if x_console_token is None or not hmac.compare_digest(x_console_token, expected):
        raise HTTPException(status_code=401, detail="missing or invalid console token")


router = APIRouter(tags=["console"])
_api = APIRouter(prefix="/console/api", dependencies=[Depends(require_console_auth)])


def _iso(dt: datetime | None) -> str | None:
    aware = ensure_aware(dt)
    return aware.isoformat() if aware is not None else None


class AgentCreateRequest(BaseModel):
    name: str
    allowed_scopes: list[str]
    user_id: uuid.UUID | None = None


class GrantCreateRequest(BaseModel):
    agent_id: uuid.UUID
    tool_name: str
    requested_scope: str


class InvokeRequest(BaseModel):
    grant_token: str
    tool_name: str
    arguments: dict = Field(default_factory=dict)
    idempotency_key: str | None = None


@router.get("/console", response_class=HTMLResponse)
async def console_page() -> HTMLResponse:
    """Serve the console single-page UI.

    The page is a build artifact shipped inside the package; reading it per
    request keeps dev iteration simple and the file is small.
    """
    try:
        html = (
            resources.files("credbroker.console").joinpath("static", "index.html").read_text()
        )
    except OSError:
        raise HTTPException(status_code=503, detail="console UI not built") from None
    return HTMLResponse(html)


@_api.get("/tools")
async def list_tools() -> list[dict]:
    return [
        {
            "name": tool.name,
            "provider": tool.provider,
            "scope": tool.scope,
            "side_effectful": tool.side_effectful,
        }
        for tool in TOOL_REGISTRY.values()
    ]


def _agent_dict(agent: AgentIdentity) -> dict:
    return {
        "id": str(agent.id),
        "user_id": str(agent.user_id),
        "name": agent.name,
        "allowed_scopes": list(agent.allowed_scopes),
        "created_at": _iso(agent.created_at),
    }


@_api.get("/agents")
async def list_agents(request: Request) -> list[dict]:
    async with request.app.state.session_factory() as session:
        agents = (
            (await session.execute(select(AgentIdentity).order_by(AgentIdentity.created_at)))
            .scalars()
            .all()
        )
        return [_agent_dict(agent) for agent in agents]


@_api.post("/agents")
async def create_agent(body: AgentCreateRequest, request: Request) -> dict:
    agent = AgentIdentity(
        user_id=body.user_id or uuid.uuid4(),
        name=body.name,
        allowed_scopes=body.allowed_scopes,
    )
    async with request.app.state.session_factory() as session:
        session.add(agent)
        await session.flush()
        payload = _agent_dict(agent)
        await session.commit()
    return payload


@_api.get("/accounts")
async def list_accounts(request: Request) -> list[dict]:
    """List connected accounts — identifying columns only, never the blobs."""
    async with request.app.state.session_factory() as session:
        accounts = (
            (
                await session.execute(
                    select(ConnectedAccount).order_by(ConnectedAccount.created_at)
                )
            )
            .scalars()
            .all()
        )
        return [
            {
                "id": str(account.id),
                "user_id": str(account.user_id),
                "provider": account.provider,
                "scopes_granted": list(account.scopes_granted),
                "expires_at": _iso(account.expires_at),
                "created_at": _iso(account.created_at),
            }
            for account in accounts
        ]


def _grant_status(grant: Grant, now: datetime) -> str:
    if grant.revoked_at is not None:
        return "revoked"
    if ensure_aware(grant.expires_at) <= now:
        return "expired"
    return "active"


@_api.get("/grants")
async def list_grants(request: Request, limit: int = Query(50, ge=1, le=500)) -> list[dict]:
    """List recent grants. The token hash stays server-side; tokens are never stored."""
    async with request.app.state.session_factory() as session:
        grants = (
            (await session.execute(select(Grant).order_by(Grant.issued_at.desc()).limit(limit)))
            .scalars()
            .all()
        )
        now = utcnow()
        return [
            {
                "id": str(grant.id),
                "agent_id": str(grant.agent_id),
                "connected_account_id": str(grant.connected_account_id),
                "tool_name": grant.tool_name,
                "scope": grant.scope,
                "issued_at": _iso(grant.issued_at),
                "expires_at": _iso(grant.expires_at),
                "revoked_at": _iso(grant.revoked_at),
                "status": _grant_status(grant, now),
            }
            for grant in grants
        ]


@_api.post("/grants")
async def create_grant(body: GrantCreateRequest, request: Request) -> dict:
    """Issue a grant, returning the signed token — here the console IS the agent."""
    state = request.app.state
    try:
        async with state.session_factory() as session:
            issued = await grants_service.request_grant(
                session=session,
                settings=state.settings,
                agent_id=body.agent_id,
                tool_name=body.tool_name,
                requested_scope=body.requested_scope,
                grant_cache=state.grant_cache,
                rate_limiter=state.rate_limiter,
            )
            payload = {
                "grant_id": str(issued.grant.id),
                "grant_token": issued.token,
                "expires_at": _iso(issued.grant.expires_at),
            }
    except CredBrokerError as exc:
        raise _http_error(exc) from None
    return payload


@_api.post("/grants/{grant_id}/revoke")
async def revoke_grant(grant_id: uuid.UUID, request: Request) -> dict:
    state = request.app.state
    try:
        async with state.session_factory() as session:
            await grants_service.revoke_grant(
                session=session, grant_id=grant_id, grant_cache=state.grant_cache
            )
    except CredBrokerError as exc:
        raise _http_error(exc) from None
    return {"revoked": True}


@_api.post("/invoke")
async def invoke_tool(body: InvokeRequest, request: Request) -> dict:
    """Invoke a tool under a grant token via the shared invoke service.

    The service never raises for deniable or failed calls — every outcome
    (including denials) comes back as data with a safe, pre-scrubbed error
    string, so the console can display it as-is.
    """
    outcome = await request.app.state.invoke_service.invoke(
        grant_token=body.grant_token,
        tool_name=body.tool_name,
        arguments=body.arguments,
        idempotency_key=body.idempotency_key,
    )
    return {
        "status": outcome.status,
        "result": outcome.result,
        "error": outcome.error,
        "latency_ms": outcome.latency_ms,
        "from_cache": outcome.from_cache,
        "denied_reason": outcome.denied_reason,
    }


@_api.post("/demo/seed")
async def demo_seed(request: Request) -> dict:
    state = request.app.state
    async with state.session_factory() as session:
        return await seed_demo(session, state.cipher)


@_api.get("/audit")
async def list_audit(request: Request, limit: int = Query(50, ge=1, le=500)) -> list[dict]:
    async with request.app.state.session_factory() as session:
        rows = (
            (
                await session.execute(
                    select(ToolCallAuditLog)
                    .order_by(ToolCallAuditLog.called_at.desc())
                    .limit(limit)
                )
            )
            .scalars()
            .all()
        )
        return [
            {
                "id": str(row.id),
                "grant_id": str(row.grant_id),
                "tool_name": row.tool_name,
                "arguments_hash": row.arguments_hash,
                "status": row.status,
                "latency_ms": row.latency_ms,
                "called_at": _iso(row.called_at),
            }
            for row in rows
        ]


router.include_router(_api)
