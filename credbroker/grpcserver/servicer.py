"""gRPC servicer for the agent-facing CredBroker API.

This layer is a thin adapter: it parses request messages, delegates to the
grant service and the invoke service, maps broker domain errors onto gRPC
status codes, and records request-boundary metrics. It never touches raw
provider credentials — agents only ever see signed grant tokens and tool
results, which is the core invariant of the broker.
"""

import functools
import logging
import uuid

import grpc
from google.protobuf import json_format, struct_pb2, timestamp_pb2

from credbroker import metrics
from credbroker.config import Settings
from credbroker.db.models import ensure_aware
from credbroker.errors import (
    ConcurrencyLimitError,
    GrantNotFoundError,
    GrantScopeMismatchError,
    NoConnectedAccountError,
    PolicyDeniedError,
    RateLimitedError,
    UnknownAgentError,
    UnknownToolError,
)
from credbroker.grants import service as grants_service
from credbroker.logging_config import scrub
from credbroker.proto import credbroker_pb2, credbroker_pb2_grpc
from credbroker.tools import TOOL_REGISTRY

logger = logging.getLogger(__name__)

# Domain error -> gRPC status code for RequestGrant denials. Exact classes
# only; the errors hierarchy has no cross-subclassing among these.
_GRANT_ERROR_CODES: dict[type[Exception], grpc.StatusCode] = {
    UnknownAgentError: grpc.StatusCode.NOT_FOUND,
    UnknownToolError: grpc.StatusCode.NOT_FOUND,
    PolicyDeniedError: grpc.StatusCode.PERMISSION_DENIED,
    GrantScopeMismatchError: grpc.StatusCode.PERMISSION_DENIED,
    NoConnectedAccountError: grpc.StatusCode.FAILED_PRECONDITION,
    ConcurrencyLimitError: grpc.StatusCode.RESOURCE_EXHAUSTED,
    RateLimitedError: grpc.StatusCode.RESOURCE_EXHAUSTED,
}
_GRANT_ERRORS = tuple(_GRANT_ERROR_CODES)


def _rpc_error_guard(method):
    """Wrap an RPC so any unhandled exception aborts INTERNAL with a fixed detail.

    grpc.aio's default handler answers UNKNOWN carrying ``str(exc)``, which
    could leak internal state to agents. The wire gets the constant string
    "internal error"; the exception type and scrubbed message go only to the
    server log. Deliberate aborts (``grpc.aio.AbortError``) pass through.
    """

    @functools.wraps(method)
    async def wrapper(self, request, context):
        try:
            return await method(self, request, context)
        except grpc.aio.AbortError:
            raise
        except Exception as exc:
            logger.error(
                "%s: unhandled %s: %s",
                method.__name__,
                type(exc).__name__,
                scrub(str(exc)),
            )
            await context.abort(grpc.StatusCode.INTERNAL, "internal error")

    return wrapper


class CredBrokerServicer(credbroker_pb2_grpc.CredBrokerServicer):
    """Async servicer wiring the broker's services to the gRPC surface.

    All collaborators are injected; the servicer owns no clients and holds no
    credential material. Sessions are opened per-RPC from the injected
    factory so each call gets its own transactional scope.
    """

    def __init__(
        self,
        *,
        settings: Settings,
        session_factory,
        grant_cache,
        rate_limiter,
        invoke_service,
    ):
        self._settings = settings
        self._session_factory = session_factory
        self._grant_cache = grant_cache
        self._rate_limiter = rate_limiter
        self._invoke_service = invoke_service

    @_rpc_error_guard
    async def RequestGrant(self, request, context):
        """Issue a short-lived, scope-limited grant token to an agent."""
        agent_id = await self._parse_uuid(request.agent_id, "agent_id", context)
        try:
            async with self._session_factory() as session:
                issued = await grants_service.request_grant(
                    session=session,
                    settings=self._settings,
                    agent_id=agent_id,
                    tool_name=request.tool_name,
                    requested_scope=request.requested_scope,
                    grant_cache=self._grant_cache,
                    rate_limiter=self._rate_limiter,
                )
        except _GRANT_ERRORS as exc:
            reason = type(exc).__name__
            metrics.GRANT_DENIALS.labels(reason=reason).inc()
            logger.info("grant denied for agent %s: %s: %s", agent_id, reason, exc)
            await context.abort(_GRANT_ERROR_CODES[type(exc)], str(exc))

        metrics.GRANTS_ISSUED.labels(
            tool_name=issued.grant.tool_name, scope=issued.grant.scope
        ).inc()
        expires_at = timestamp_pb2.Timestamp()
        expires_at.FromDatetime(ensure_aware(issued.grant.expires_at))
        return credbroker_pb2.GrantResponse(
            grant_token=issued.token,
            expires_at=expires_at,
            grant_id=str(issued.grant.id),
        )

    @_rpc_error_guard
    async def InvokeTool(self, request, context):
        """Execute a tool call under a grant token.

        The invoke service performs every check (token verification,
        revocation, rate limits, idempotency) and the provider call itself;
        this method only translates the outcome onto the wire. Denied and
        failed outcomes become gRPC aborts carrying the outcome's safe,
        pre-scrubbed error string; denials map to PERMISSION_DENIED except
        rate limiting, which maps to RESOURCE_EXHAUSTED.
        """
        arguments = json_format.MessageToDict(request.arguments)
        outcome = await self._invoke_service.invoke(
            grant_token=request.grant_token,
            tool_name=request.tool_name,
            arguments=arguments,
            idempotency_key=request.idempotency_key or None,
        )
        # Only registered tool names may become metric label values; anything
        # else is caller-controlled and would grow /metrics without bound.
        tool_label = request.tool_name if request.tool_name in TOOL_REGISTRY else "unknown"
        metrics.INVOCATIONS.labels(tool_name=tool_label, status=outcome.status).inc()
        if outcome.status == "denied":
            code = (
                grpc.StatusCode.RESOURCE_EXHAUSTED
                if outcome.denied_reason == "rate_limited"
                else grpc.StatusCode.PERMISSION_DENIED
            )
            await context.abort(code, outcome.error or "invocation denied")
        if outcome.status == "failed":
            await context.abort(
                grpc.StatusCode.UNAVAILABLE, outcome.error or "tool call failed"
            )

        metrics.INVOKE_LATENCY.labels(tool_name=tool_label).observe(
            outcome.latency_ms / 1000.0
        )
        result = struct_pb2.Struct()
        json_format.ParseDict(outcome.result or {}, result)
        return credbroker_pb2.InvokeResponse(result=result, status=outcome.status)

    @_rpc_error_guard
    async def RevokeGrant(self, request, context):
        """Revoke a grant immediately; idempotent for already-revoked grants."""
        grant_id = await self._parse_uuid(request.grant_id, "grant_id", context)
        try:
            async with self._session_factory() as session:
                await grants_service.revoke_grant(
                    session=session, grant_id=grant_id, grant_cache=self._grant_cache
                )
        except GrantNotFoundError as exc:
            await context.abort(grpc.StatusCode.NOT_FOUND, str(exc))

        metrics.GRANTS_REVOKED.inc()
        return credbroker_pb2.RevokeResponse(revoked=True)

    @staticmethod
    async def _parse_uuid(raw: str, field: str, context) -> uuid.UUID:
        """Parse a request UUID field, aborting with INVALID_ARGUMENT if malformed."""
        try:
            return uuid.UUID(raw)
        except (ValueError, AttributeError, TypeError):
            await context.abort(
                grpc.StatusCode.INVALID_ARGUMENT, f"{field} must be a valid UUID"
            )
