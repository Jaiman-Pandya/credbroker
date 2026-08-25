"""Tests for grant issuance and revocation (credbroker.grants.service)."""

import uuid
from datetime import timedelta

import pytest
from sqlalchemy import select, update

from credbroker.db.models import AgentIdentity, ConnectedAccount, Grant, utcnow
from credbroker.errors import (
    ConcurrencyLimitError,
    GrantNotFoundError,
    GrantScopeMismatchError,
    NoConnectedAccountError,
    PolicyDeniedError,
    UnknownAgentError,
    UnknownToolError,
)
from credbroker.grants.service import request_grant, revoke_grant
from credbroker.grants.tokens import hash_token, verify_grant_token

# One user owns both the agent and the connected account in these tests.
USER_ID = uuid.uuid4()


@pytest.fixture
async def agent(session):
    agent = AgentIdentity(user_id=USER_ID, name="test-agent", allowed_scopes=["drive.read"])
    session.add(agent)
    await session.commit()
    return agent


@pytest.fixture
async def account(session):
    account = ConnectedAccount(
        user_id=USER_ID,
        provider="google",
        encrypted_access_token=b"\x01opaque-encrypted-access",
        encrypted_refresh_token=b"\x01opaque-encrypted-refresh",
        scopes_granted=["https://www.googleapis.com/auth/drive.readonly"],
        expires_at=utcnow() + timedelta(hours=1),
    )
    session.add(account)
    await session.commit()
    return account


async def test_happy_path_issues_verifiable_token(session, settings, agent, account):
    issued = await request_grant(
        session=session,
        settings=settings,
        agent_id=agent.id,
        tool_name="drive.read",
        requested_scope="read",
    )

    claims = verify_grant_token(issued.token, settings)
    assert claims.grant_id == issued.grant.id
    assert claims.agent_id == agent.id
    assert claims.tool_name == "drive.read"
    assert claims.scope == "read"

    assert issued.grant.connected_account_id == account.id
    assert issued.grant.revoked_at is None
    ttl = issued.grant.expires_at - issued.grant.issued_at
    assert ttl == timedelta(seconds=settings.grant_token_ttl_seconds)


async def test_only_token_hash_is_persisted(session, settings, agent, account):
    issued = await request_grant(
        session=session,
        settings=settings,
        agent_id=agent.id,
        tool_name="drive.read",
        requested_scope="read",
    )

    row = (await session.execute(select(Grant))).scalar_one()
    assert row.grant_token_hash == hash_token(issued.token)
    assert issued.token not in row.grant_token_hash


async def test_newest_connected_account_is_selected(session, settings, agent, account):
    """Among the agent's own user's accounts, the newest wins."""
    newer = ConnectedAccount(
        user_id=USER_ID,
        provider="google",
        encrypted_access_token=b"\x01opaque-newer-access",
        scopes_granted=[],
        created_at=utcnow() + timedelta(seconds=5),
    )
    session.add(newer)
    await session.commit()

    issued = await request_grant(
        session=session,
        settings=settings,
        agent_id=agent.id,
        tool_name="drive.read",
        requested_scope="read",
    )

    assert issued.grant.connected_account_id == newer.id


async def test_unknown_agent(session, settings, account):
    with pytest.raises(UnknownAgentError):
        await request_grant(
            session=session,
            settings=settings,
            agent_id=uuid.uuid4(),
            tool_name="drive.read",
            requested_scope="read",
        )


async def test_unknown_tool(session, settings, agent, account):
    with pytest.raises(UnknownToolError):
        await request_grant(
            session=session,
            settings=settings,
            agent_id=agent.id,
            tool_name="no.such.tool",
            requested_scope="read",
        )


async def test_policy_denied_for_disallowed_tool(session, settings, account):
    locked_down = AgentIdentity(user_id=USER_ID, name="locked-down", allowed_scopes=[])
    session.add(locked_down)
    await session.commit()

    with pytest.raises(PolicyDeniedError):
        await request_grant(
            session=session,
            settings=settings,
            agent_id=locked_down.id,
            tool_name="drive.read",
            requested_scope="read",
        )


async def test_scope_mismatch(session, settings, agent, account):
    with pytest.raises(GrantScopeMismatchError):
        await request_grant(
            session=session,
            settings=settings,
            agent_id=agent.id,
            tool_name="drive.read",
            requested_scope="write",
        )


async def test_no_connected_account(session, settings, agent):
    with pytest.raises(NoConnectedAccountError):
        await request_grant(
            session=session,
            settings=settings,
            agent_id=agent.id,
            tool_name="drive.read",
            requested_scope="read",
        )


async def test_grant_never_binds_to_another_users_account(session, settings, agent):
    """A different user's account — even a newer one — must never be used."""
    other_users_account = ConnectedAccount(
        user_id=uuid.uuid4(),  # not the agent's user
        provider="google",
        encrypted_access_token=b"\x01someone-elses-encrypted-token",
        scopes_granted=["https://www.googleapis.com/auth/drive.readonly"],
        expires_at=utcnow() + timedelta(hours=1),
    )
    session.add(other_users_account)
    await session.commit()

    with pytest.raises(NoConnectedAccountError):
        await request_grant(
            session=session,
            settings=settings,
            agent_id=agent.id,
            tool_name="drive.read",
            requested_scope="read",
        )


async def test_concurrency_limit_blocks_second_active_grant(session, settings, agent, account):
    assert settings.max_active_grants_per_agent_scope == 1
    await request_grant(
        session=session,
        settings=settings,
        agent_id=agent.id,
        tool_name="drive.read",
        requested_scope="read",
    )

    with pytest.raises(ConcurrencyLimitError):
        await request_grant(
            session=session,
            settings=settings,
            agent_id=agent.id,
            tool_name="drive.read",
            requested_scope="read",
        )


async def test_expired_grant_does_not_count_toward_limit(session, settings, agent, account):
    first = await request_grant(
        session=session,
        settings=settings,
        agent_id=agent.id,
        tool_name="drive.read",
        requested_scope="read",
    )
    await session.execute(
        update(Grant)
        .where(Grant.id == first.grant.id)
        .values(expires_at=utcnow() - timedelta(seconds=1))
    )
    await session.commit()

    second = await request_grant(
        session=session,
        settings=settings,
        agent_id=agent.id,
        tool_name="drive.read",
        requested_scope="read",
    )
    assert second.grant.id != first.grant.id


async def test_revoked_grant_does_not_count_toward_limit(session, settings, agent, account):
    first = await request_grant(
        session=session,
        settings=settings,
        agent_id=agent.id,
        tool_name="drive.read",
        requested_scope="read",
    )
    await revoke_grant(session=session, grant_id=first.grant.id)

    second = await request_grant(
        session=session,
        settings=settings,
        agent_id=agent.id,
        tool_name="drive.read",
        requested_scope="read",
    )
    assert second.grant.id != first.grant.id


async def test_revoke_sets_revoked_at(session, settings, agent, account):
    issued = await request_grant(
        session=session,
        settings=settings,
        agent_id=agent.id,
        tool_name="drive.read",
        requested_scope="read",
    )

    revoked = await revoke_grant(session=session, grant_id=issued.grant.id)

    assert revoked.id == issued.grant.id
    assert revoked.revoked_at is not None


async def test_revoke_is_idempotent(session, settings, agent, account):
    issued = await request_grant(
        session=session,
        settings=settings,
        agent_id=agent.id,
        tool_name="drive.read",
        requested_scope="read",
    )

    first = await revoke_grant(session=session, grant_id=issued.grant.id)
    first_revoked_at = first.revoked_at
    second = await revoke_grant(session=session, grant_id=issued.grant.id)

    assert second.id == first.id
    assert second.revoked_at == first_revoked_at


async def test_revoke_missing_grant_raises(session):
    with pytest.raises(GrantNotFoundError):
        await revoke_grant(session=session, grant_id=uuid.uuid4())
