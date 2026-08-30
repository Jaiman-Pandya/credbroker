"""Tests for the gRPC servicer.

The servicer is instantiated directly (no network) with the real grant
service over SQLite and real fakeredis-backed cache/limiter. The invoke
service is a duck-typed stub because the real implementation is a separate
build unit; the servicer only depends on its ``invoke(...) -> outcome``
shape. The gRPC context is mocked with an ``abort`` that raises a sentinel
recording the status code, mirroring grpc.aio abort semantics.
"""

import logging
import uuid
from datetime import UTC, timedelta
from types import SimpleNamespace

import grpc
import jwt as pyjwt
import pytest
from google.protobuf import json_format, struct_pb2

from credbroker import logging_config, metrics
from credbroker.cache.grants_cache import GrantCache
from credbroker.cache.ratelimit import RateLimiter
from credbroker.db.models import AgentIdentity, ConnectedAccount, Grant, utcnow
from credbroker.grants.tokens import hash_token, verify_grant_token
from credbroker.grpcserver.servicer import CredBrokerServicer
from credbroker.proto import credbroker_pb2

TOOL_NAME = "drive.read"
# One user owns both the agent and the connected account in these tests.
USER_ID = uuid.uuid4()
TOOL_SCOPE = "read"


@pytest.fixture(autouse=True)
def _clean_secret_registry():
    logging_config.clear_registry()
    yield
    logging_config.clear_registry()


class AbortSentinel(grpc.aio.AbortError):
    """Raised by the fake context's abort; subclasses grpc.aio.AbortError so
    the servicer's internal-error guard lets it propagate like a real abort."""

    def __init__(self, code: grpc.StatusCode, details: str):
        super().__init__(details)
        self.code = code
        self.details = details


class FakeContext:
    """Minimal grpc.aio ServicerContext double: abort raises and records."""

    def __init__(self):
        self.code: grpc.StatusCode | None = None
        self.details: str | None = None

    async def abort(self, code: grpc.StatusCode, details: str = ""):
        self.code = code
        self.details = details
        raise AbortSentinel(code, details)


class StubInvokeService:
    """Duck-typed stand-in for credbroker.invoke.service.InvokeService."""

    def __init__(self, outcome):
        self.outcome = outcome
        self.calls: list[dict] = []

    async def invoke(self, *, grant_token, tool_name, arguments, idempotency_key=None):
        self.calls.append(
            {
                "grant_token": grant_token,
                "tool_name": tool_name,
                "arguments": arguments,
                "idempotency_key": idempotency_key,
            }
        )
        return self.outcome


def success_outcome(result: dict, latency_ms: int = 42) -> SimpleNamespace:
    return SimpleNamespace(
        status="success",
        result=result,
        error=None,
        latency_ms=latency_ms,
        from_cache=False,
        denied_reason=None,
    )


def denied_outcome(error: str, denied_reason: str, latency_ms: int = 3) -> SimpleNamespace:
    return SimpleNamespace(
        status="denied",
        result=None,
        error=error,
        latency_ms=latency_ms,
        from_cache=False,
        denied_reason=denied_reason,
    )


def counter_value(counter, **labels) -> float:
    return counter.labels(**labels)._value.get()


@pytest.fixture
async def agent(session) -> AgentIdentity:
    agent = AgentIdentity(user_id=USER_ID, name="test-agent", allowed_scopes=[TOOL_NAME])
    session.add(agent)
    await session.commit()
    return agent


@pytest.fixture
async def account(session) -> ConnectedAccount:
    account = ConnectedAccount(
        user_id=USER_ID,
        provider="google",
        encrypted_access_token=b"opaque-encrypted-access-token",
        encrypted_refresh_token=b"opaque-encrypted-refresh-token",
        scopes_granted=["https://www.googleapis.com/auth/drive.readonly"],
        expires_at=utcnow() + timedelta(hours=1),
    )
    session.add(account)
    await session.commit()
    return account


@pytest.fixture
def grant_cache(redis_client) -> GrantCache:
    return GrantCache(redis_client)


@pytest.fixture
def rate_limiter(redis_client) -> RateLimiter:
    return RateLimiter(redis_client)


@pytest.fixture
def stub_invoke() -> StubInvokeService:
    return StubInvokeService(success_outcome({"files": []}))


@pytest.fixture
def servicer(settings, session_factory, grant_cache, rate_limiter, stub_invoke):
    return CredBrokerServicer(
        settings=settings,
        session_factory=session_factory,
        grant_cache=grant_cache,
        rate_limiter=rate_limiter,
        invoke_service=stub_invoke,
    )


def grant_request(agent_id: str) -> credbroker_pb2.GrantRequest:
    return credbroker_pb2.GrantRequest(
        agent_id=agent_id, tool_name=TOOL_NAME, requested_scope=TOOL_SCOPE
    )


async def test_request_grant_happy_path(servicer, settings, agent, account):
    before = counter_value(metrics.GRANTS_ISSUED, tool_name=TOOL_NAME, scope=TOOL_SCOPE)

    response = await servicer.RequestGrant(grant_request(str(agent.id)), FakeContext())

    assert response.grant_token
    # The token must verify against the JWT public key with pinned claims.
    decoded = pyjwt.decode(
        response.grant_token,
        settings.jwt_public_key_pem,
        algorithms=["RS256"],
        issuer=settings.jwt_issuer,
    )
    assert decoded["sub"] == str(agent.id)
    assert decoded["jti"] == response.grant_id
    claims = verify_grant_token(response.grant_token, settings)
    assert claims.agent_id == agent.id
    assert claims.grant_id == uuid.UUID(response.grant_id)
    assert claims.tool_name == TOOL_NAME
    assert claims.scope == TOOL_SCOPE

    assert response.expires_at.ToDatetime(tzinfo=UTC) > utcnow()
    after = counter_value(metrics.GRANTS_ISSUED, tool_name=TOOL_NAME, scope=TOOL_SCOPE)
    assert after == before + 1


async def test_request_grant_never_returns_raw_credentials(servicer, agent, account):
    """The response carries only the signed grant token, never account tokens."""
    response = await servicer.RequestGrant(grant_request(str(agent.id)), FakeContext())
    serialized = response.SerializeToString()
    assert b"opaque-encrypted-access-token" not in serialized
    assert b"opaque-encrypted-refresh-token" not in serialized


async def test_request_grant_invalid_uuid(servicer):
    with pytest.raises(AbortSentinel) as excinfo:
        await servicer.RequestGrant(grant_request("not-a-uuid"), FakeContext())
    assert excinfo.value.code == grpc.StatusCode.INVALID_ARGUMENT


async def test_request_grant_unknown_agent(servicer, account):
    with pytest.raises(AbortSentinel) as excinfo:
        await servicer.RequestGrant(grant_request(str(uuid.uuid4())), FakeContext())
    assert excinfo.value.code == grpc.StatusCode.NOT_FOUND


async def test_request_grant_unknown_tool(servicer, session, account):
    agent = AgentIdentity(user_id=USER_ID, name="tooly", allowed_scopes=["no.such.tool"])
    session.add(agent)
    await session.commit()
    request = credbroker_pb2.GrantRequest(
        agent_id=str(agent.id), tool_name="no.such.tool", requested_scope="read"
    )
    with pytest.raises(AbortSentinel) as excinfo:
        await servicer.RequestGrant(request, FakeContext())
    assert excinfo.value.code == grpc.StatusCode.NOT_FOUND


async def test_request_grant_policy_denied(servicer, session, account):
    """An agent whose policy does not allow the tool maps to PERMISSION_DENIED."""
    agent = AgentIdentity(user_id=USER_ID, name="unprivileged", allowed_scopes=[])
    session.add(agent)
    await session.commit()
    before = counter_value(metrics.GRANT_DENIALS, reason="PolicyDeniedError")

    with pytest.raises(AbortSentinel) as excinfo:
        await servicer.RequestGrant(grant_request(str(agent.id)), FakeContext())

    assert excinfo.value.code == grpc.StatusCode.PERMISSION_DENIED
    assert counter_value(metrics.GRANT_DENIALS, reason="PolicyDeniedError") == before + 1


async def test_request_grant_scope_mismatch(servicer, agent, account):
    request = credbroker_pb2.GrantRequest(
        agent_id=str(agent.id), tool_name=TOOL_NAME, requested_scope="write"
    )
    with pytest.raises(AbortSentinel) as excinfo:
        await servicer.RequestGrant(request, FakeContext())
    assert excinfo.value.code == grpc.StatusCode.PERMISSION_DENIED


async def test_request_grant_no_connected_account(servicer, agent):
    with pytest.raises(AbortSentinel) as excinfo:
        await servicer.RequestGrant(grant_request(str(agent.id)), FakeContext())
    assert excinfo.value.code == grpc.StatusCode.FAILED_PRECONDITION


async def test_request_grant_concurrency_limit(servicer, settings, agent, account):
    """A second active grant for the same agent/tool/scope is RESOURCE_EXHAUSTED."""
    assert settings.max_active_grants_per_agent_scope == 1
    await servicer.RequestGrant(grant_request(str(agent.id)), FakeContext())
    with pytest.raises(AbortSentinel) as excinfo:
        await servicer.RequestGrant(grant_request(str(agent.id)), FakeContext())
    assert excinfo.value.code == grpc.StatusCode.RESOURCE_EXHAUSTED


def invoke_request(arguments: dict, **kwargs) -> credbroker_pb2.InvokeRequest:
    args_struct = struct_pb2.Struct()
    json_format.ParseDict(arguments, args_struct)
    return credbroker_pb2.InvokeRequest(
        grant_token="grant-token", tool_name=TOOL_NAME, arguments=args_struct, **kwargs
    )


async def test_invoke_success_returns_struct_result(servicer, stub_invoke):
    result = {"files": [{"id": "f1", "name": "Design doc"}], "nextPageToken": "tok"}
    stub_invoke.outcome = success_outcome(result)
    before = counter_value(metrics.INVOCATIONS, tool_name=TOOL_NAME, status="success")

    response = await servicer.InvokeTool(
        invoke_request({"query": "name contains 'doc'"}), FakeContext()
    )

    assert response.status == "success"
    assert json_format.MessageToDict(response.result) == result
    assert counter_value(metrics.INVOCATIONS, tool_name=TOOL_NAME, status="success") == before + 1
    # Arguments crossed the boundary as a plain dict; empty key became None.
    assert stub_invoke.calls == [
        {
            "grant_token": "grant-token",
            "tool_name": TOOL_NAME,
            "arguments": {"query": "name contains 'doc'"},
            "idempotency_key": None,
        }
    ]


async def test_invoke_passes_idempotency_key(servicer, stub_invoke):
    await servicer.InvokeTool(
        invoke_request({}, idempotency_key="idem-123"), FakeContext()
    )
    assert stub_invoke.calls[0]["idempotency_key"] == "idem-123"


async def test_invoke_denied_maps_to_permission_denied(servicer, stub_invoke):
    stub_invoke.outcome = denied_outcome("grant is revoked", "revoked")
    before = counter_value(metrics.INVOCATIONS, tool_name=TOOL_NAME, status="denied")

    with pytest.raises(AbortSentinel) as excinfo:
        await servicer.InvokeTool(invoke_request({}), FakeContext())

    assert excinfo.value.code == grpc.StatusCode.PERMISSION_DENIED
    assert excinfo.value.details == "grant is revoked"
    assert counter_value(metrics.INVOCATIONS, tool_name=TOOL_NAME, status="denied") == before + 1


async def test_invoke_rate_limited_maps_to_resource_exhausted(servicer, stub_invoke):
    """Rate limiting is a throttling signal, not a permissions one."""
    stub_invoke.outcome = denied_outcome("invoke rate limit exceeded", "rate_limited")
    with pytest.raises(AbortSentinel) as excinfo:
        await servicer.InvokeTool(invoke_request({}), FakeContext())
    assert excinfo.value.code == grpc.StatusCode.RESOURCE_EXHAUSTED
    assert excinfo.value.details == "invoke rate limit exceeded"


async def test_invoke_failed_maps_to_unavailable(servicer, stub_invoke):
    stub_invoke.outcome = SimpleNamespace(
        status="failed",
        result=None,
        error="provider unavailable",
        latency_ms=900,
        from_cache=False,
        denied_reason=None,
    )
    with pytest.raises(AbortSentinel) as excinfo:
        await servicer.InvokeTool(invoke_request({}), FakeContext())
    assert excinfo.value.code == grpc.StatusCode.UNAVAILABLE
    assert excinfo.value.details == "provider unavailable"


async def test_invoke_unregistered_tool_labels_metrics_unknown(servicer, stub_invoke):
    """A caller-invented tool name must not mint a new /metrics label value."""
    rogue = f"rogue.tool.{uuid.uuid4().hex}"
    before = counter_value(metrics.INVOCATIONS, tool_name="unknown", status="success")

    request = credbroker_pb2.InvokeRequest(
        grant_token="grant-token", tool_name=rogue, arguments=struct_pb2.Struct()
    )
    await servicer.InvokeTool(request, FakeContext())

    assert counter_value(metrics.INVOCATIONS, tool_name="unknown", status="success") == before + 1
    labeled = {
        sample.labels.get("tool_name")
        for metric in (metrics.INVOCATIONS, metrics.INVOKE_LATENCY)
        for family in metric.collect()
        for sample in family.samples
    }
    assert rogue not in labeled
    assert "unknown" in labeled
    # The raw name still reaches the invoke service, whose checks deny it.
    assert stub_invoke.calls[0]["tool_name"] == rogue


class RaisingInvokeService:
    """Invoke-service double whose invoke raises, simulating a server bug."""

    def __init__(self, exc: Exception):
        self.exc = exc

    async def invoke(self, **kwargs):
        raise self.exc


async def test_invoke_unhandled_error_aborts_internal_fixed_detail(
    settings, session_factory, grant_cache, rate_limiter, caplog
):
    """A bug in the invoke path must never put str(exc) on the wire."""
    logging_config.register_secret("hyper-secret-value")
    servicer = CredBrokerServicer(
        settings=settings,
        session_factory=session_factory,
        grant_cache=grant_cache,
        rate_limiter=rate_limiter,
        invoke_service=RaisingInvokeService(RuntimeError("boom with SECRET hyper-secret-value")),
    )

    with caplog.at_level(logging.ERROR, logger="credbroker.grpcserver.servicer"):
        with pytest.raises(AbortSentinel) as excinfo:
            await servicer.InvokeTool(invoke_request({}), FakeContext())

    assert excinfo.value.code == grpc.StatusCode.INTERNAL
    assert excinfo.value.details == "internal error"
    # Server-side log keeps the type name but scrubs registered secrets.
    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert "RuntimeError" in logged
    assert "hyper-secret-value" not in logged
    assert logging_config.REDACTED in logged


async def test_request_grant_unhandled_error_aborts_internal(
    settings, grant_cache, rate_limiter, stub_invoke
):
    """The guard covers every RPC, not just InvokeTool."""

    def broken_session_factory():
        raise RuntimeError("connection pool exploded")

    servicer = CredBrokerServicer(
        settings=settings,
        session_factory=broken_session_factory,
        grant_cache=grant_cache,
        rate_limiter=rate_limiter,
        invoke_service=stub_invoke,
    )
    with pytest.raises(AbortSentinel) as excinfo:
        await servicer.RequestGrant(grant_request(str(uuid.uuid4())), FakeContext())
    assert excinfo.value.code == grpc.StatusCode.INTERNAL
    assert excinfo.value.details == "internal error"


async def test_invoke_deliberate_aborts_pass_through_guard(servicer, stub_invoke):
    """The internal-error guard must not rewrap an intentional abort's code."""
    stub_invoke.outcome = denied_outcome("grant has expired", "expired")
    with pytest.raises(AbortSentinel) as excinfo:
        await servicer.InvokeTool(invoke_request({}), FakeContext())
    assert excinfo.value.code == grpc.StatusCode.PERMISSION_DENIED
    assert excinfo.value.details == "grant has expired"


async def test_revoke_grant_lifecycle(servicer, session, grant_cache, agent, account):
    """Revoking an issued grant flips the DB row and the revocation cache."""
    issued = await servicer.RequestGrant(grant_request(str(agent.id)), FakeContext())
    grant_id = uuid.UUID(issued.grant_id)

    response = await servicer.RevokeGrant(
        credbroker_pb2.RevokeRequest(grant_id=issued.grant_id), FakeContext()
    )

    assert response.revoked is True
    grant = await session.get(Grant, grant_id)
    assert grant is not None and grant.revoked_at is not None
    assert await grant_cache.is_revoked(hash_token(issued.grant_token)) is True

    # Idempotent: revoking again still succeeds.
    again = await servicer.RevokeGrant(
        credbroker_pb2.RevokeRequest(grant_id=issued.grant_id), FakeContext()
    )
    assert again.revoked is True


async def test_revoke_grant_missing(servicer):
    with pytest.raises(AbortSentinel) as excinfo:
        await servicer.RevokeGrant(
            credbroker_pb2.RevokeRequest(grant_id=str(uuid.uuid4())), FakeContext()
        )
    assert excinfo.value.code == grpc.StatusCode.NOT_FOUND


async def test_revoke_grant_invalid_uuid(servicer):
    with pytest.raises(AbortSentinel) as excinfo:
        await servicer.RevokeGrant(
            credbroker_pb2.RevokeRequest(grant_id="nope"), FakeContext()
        )
    assert excinfo.value.code == grpc.StatusCode.INVALID_ARGUMENT
