"""Grant issuance and revocation.

``request_grant`` is the policy chokepoint: agent policy, scope match, and
account resolution all run here.

No raw provider credential is touched anywhere in this module: the grant
binds to a ConnectedAccount row by id only, and only the SHA-256 hash of the
issued token is persisted.
"""

import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from credbroker.config import Settings
from credbroker.db.models import AgentIdentity, ConnectedAccount, Grant, utcnow
from credbroker.errors import (
    GrantNotFoundError,
    GrantScopeMismatchError,
    NoConnectedAccountError,
    PolicyDeniedError,
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
) -> IssuedGrant:
    """Issue a short-lived signed grant for one agent + tool + scope.

    Raises:
        UnknownAgentError: no such agent identity.
        UnknownToolError: no such tool adapter registered.
        PolicyDeniedError: the tool is not in the agent's ``allowed_scopes``.
        GrantScopeMismatchError: ``requested_scope`` != the tool's scope.
        NoConnectedAccountError: the agent's user has no connected account for
            the tool's provider.
    """
    agent = await session.get(AgentIdentity, agent_id)
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

    return IssuedGrant(token=token, grant=grant)


async def revoke_grant(
    *,
    session: AsyncSession,
    grant_id: uuid.UUID,
) -> Grant:
    """Revoke a grant immediately. Idempotent: re-revoking is a no-op.

    The database row is the source of truth for revocation.

    Raises:
        GrantNotFoundError: no grant with this id exists.
    """
    grant = await session.get(Grant, grant_id)
    if grant is None:
        raise GrantNotFoundError(f"grant not found: {grant_id}")

    if grant.revoked_at is None:
        grant.revoked_at = utcnow()
        await session.commit()

    return grant
