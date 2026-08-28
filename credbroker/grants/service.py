"""Grant issuance and revocation.

``request_grant`` is the policy chokepoint: rate limit, agent policy, scope
match, account resolution, and the active-grant concurrency limit all run here
under a row lock on the agent (``SELECT ... FOR UPDATE``; a no-op on SQLite,
serializing on PostgreSQL) so concurrent requests cannot race past the limit.

No raw provider credential is touched anywhere in this module: the grant
binds to a ConnectedAccount row by id only, and only the SHA-256 hash of the
issued token is persisted.

Collaborators are injected: ``grant_cache`` (``record_issued`` /
``record_revoked``) and ``rate_limiter`` (``check``) are optional so callers
without Redis — and tests — can pass None or a fake.
"""

import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from credbroker.config import Settings
from credbroker.db.models import AgentIdentity, ConnectedAccount, Grant, utcnow
from credbroker.errors import (
    ConcurrencyLimitError,
    GrantNotFoundError,
    GrantScopeMismatchError,
    NoConnectedAccountError,
    PolicyDeniedError,
    RateLimitedError,
    UnknownAgentError,
)
from credbroker.grants.tokens import hash_token, sign_grant_token
from credbroker.tools import get_tool


@dataclass
class IssuedGrant:
    """The signed token to hand to the agent, plus the persisted grant row."""

    token: str
    grant: Grant


async def request_grant(
    *,
    session: AsyncSession,
    settings: Settings,
    agent_id: uuid.UUID,
    tool_name: str,
    requested_scope: str,
    grant_cache=None,
    rate_limiter=None,
) -> IssuedGrant:
    """Issue a short-lived signed grant for one agent + tool + scope.

    Raises:
        RateLimitedError: the agent exceeded its grant-request rate limit.
        UnknownAgentError: no such agent identity.
        UnknownToolError: no such tool adapter registered.
        PolicyDeniedError: the tool is not in the agent's ``allowed_scopes``.
        GrantScopeMismatchError: ``requested_scope`` != the tool's scope.
        NoConnectedAccountError: the agent's user has no connected account for
            the tool's provider.
        ConcurrencyLimitError: the agent already holds the maximum number of
            active grants for this tool + scope.
    """
    if rate_limiter is not None:
        allowed = await rate_limiter.check(
            f"grants:{agent_id}", settings.grants_per_minute_per_agent
        )
        if not allowed:
            raise RateLimitedError("grant request rate limit exceeded")

    # Row lock on the agent serializes concurrent requests for the same agent
    # (on PostgreSQL) so the concurrency count below cannot be raced.
    agent = await session.get(AgentIdentity, agent_id, with_for_update=True)
    if agent is None:
        raise UnknownAgentError(f"unknown agent: {agent_id}")

    tool = get_tool(tool_name)
    if tool_name not in agent.allowed_scopes:
        raise PolicyDeniedError(f"agent is not permitted to request tool {tool_name!r}")
    if requested_scope != tool.scope:
        raise GrantScopeMismatchError(
            f"tool {tool_name!r} has scope {tool.scope!r}, not {requested_scope!r}"
        )

    # Bind strictly to the agent's own user: a grant must never attach to
    # another user's connected account, no matter how recently it was added.
    account = (
        await session.execute(
            select(ConnectedAccount)
            .where(
                ConnectedAccount.user_id == agent.user_id,
                ConnectedAccount.provider == tool.provider,
            )
            .order_by(ConnectedAccount.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if account is None:
        raise NoConnectedAccountError(
            f"user has no connected account for provider {tool.provider!r}"
        )

    now = utcnow()
    active_count = (
        await session.execute(
            select(func.count())
            .select_from(Grant)
            .where(
                Grant.agent_id == agent_id,
                Grant.tool_name == tool_name,
                Grant.scope == requested_scope,
                Grant.revoked_at.is_(None),
                Grant.expires_at > now,
            )
        )
    ).scalar_one()
    if active_count >= settings.max_active_grants_per_agent_scope:
        raise ConcurrencyLimitError(
            f"agent already holds {active_count} active grant(s) for {tool_name!r}"
        )

    grant_id = uuid.uuid4()
    expires_at = now + timedelta(seconds=settings.grant_token_ttl_seconds)
    token = sign_grant_token(
        settings=settings,
        grant_id=grant_id,
        agent_id=agent_id,
        tool_name=tool_name,
        scope=requested_scope,
        issued_at=now,
        expires_at=expires_at,
    )
    token_hash = hash_token(token)
    grant = Grant(
        id=grant_id,
        agent_id=agent_id,
        connected_account_id=account.id,
        tool_name=tool_name,
        scope=requested_scope,
        grant_token_hash=token_hash,
        issued_at=now,
        expires_at=expires_at,
    )
    session.add(grant)
    await session.commit()

    if grant_cache is not None:
        await grant_cache.record_issued(token_hash, settings.grant_token_ttl_seconds)

    return IssuedGrant(token=token, grant=grant)


async def revoke_grant(
    *,
    session: AsyncSession,
    grant_id: uuid.UUID,
    grant_cache=None,
) -> Grant:
    """Revoke a grant immediately. Idempotent: re-revoking is a no-op.

    The Redis revocation marker is (re-)written on every call so the fast
    revocation check in the invoke path converges even if an earlier cache
    write was lost; the database row remains the source of truth.

    Raises:
        GrantNotFoundError: no grant with this id exists.
    """
    grant = await session.get(Grant, grant_id)
    if grant is None:
        raise GrantNotFoundError(f"grant not found: {grant_id}")

    token_hash = grant.grant_token_hash
    if grant.revoked_at is None:
        grant.revoked_at = utcnow()
        await session.commit()

    if grant_cache is not None:
        await grant_cache.record_revoked(token_hash)

    return grant
