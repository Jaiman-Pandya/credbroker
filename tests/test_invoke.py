"""Tests for the invoke path (credbroker.invoke.service / audit).

Everything runs against SQLite, fakeredis, and an httpx.MockTransport that
plays both the Google Drive API and the OAuth token endpoint — no network.
Each test asserts the audit trail alongside the outcome, since one audit row
per resolved invocation is part of the invoke contract.
"""

import logging
import uuid
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import select, update

from credbroker.cache.grants_cache import GrantCache
from credbroker.cache.ratelimit import RateLimiter
from credbroker.crypto.kms import build_token_cipher
from credbroker.db.models import (
    AgentIdentity,
    ConnectedAccount,
    Grant,
    ToolCallAuditLog,
    ensure_aware,
    utcnow,
)
from credbroker.grants.service import request_grant, revoke_grant
from credbroker.grants.tokens import sign_grant_token
from credbroker.invoke.audit import hash_arguments
from credbroker.invoke.service import InvokeService
from credbroker.logging_config import clear_registry
from credbroker.reliability.idempotency import IdempotencyStore

ACCESS_TOKEN = "raw-google-access-token-0123456789abcdef"
# One user owns both the agent and the connected account in these tests.
USER_ID = uuid.uuid4()
REFRESH_TOKEN = "raw-google-refresh-token-0123456789abcdef"
REFRESHED_ACCESS_TOKEN = "refreshed-google-access-token-fedcba9876"

DRIVE_RESULT = {"files": [{"id": "f1", "name": "notes.txt", "mimeType": "text/plain"}]}
ARGUMENTS = {"query": "name contains 'notes'", "page_size": 10}


class FakeGoogle:
    """MockTransport handler playing the Drive API and the OAuth token endpoint."""

    def __init__(self):
        self.drive_requests: list[httpx.Request] = []
        self.token_requests: list[httpx.Request] = []
        self.drive_status = 200
        # When set, the token endpoint raises instead of answering — a
        # transport failure mid-refresh.
        self.token_error: Exception | None = None
        # When set, drive requests raise this instead of answering.
        self.drive_error: Exception | None = None
        # When set, drive requests presenting this bearer token get a 401
        # (a token invalidated provider-side despite looking fresh).
        self.reject_bearer: str | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == "oauth2.googleapis.com":
            self.token_requests.append(request)
            if self.token_error is not None:
                raise self.token_error
            return httpx.Response(
                200,
                json={
                    "access_token": REFRESHED_ACCESS_TOKEN,
                    "expires_in": 3600,
                    "scope": "https://www.googleapis.com/auth/drive.readonly",
                },
            )
        self.drive_requests.append(request)
        if self.drive_error is not None:
            raise self.drive_error
        if (
            self.reject_bearer is not None
            and request.headers.get("authorization") == f"Bearer {self.reject_bearer}"
        ):
            return httpx.Response(401, json={"error": {"message": "invalid credentials"}})
        if self.drive_status >= 400:
            return httpx.Response(self.drive_status, json={"error": {"message": "boom"}})
        return httpx.Response(200, json=DRIVE_RESULT)


class DenyAllRateLimiter:
    """Rate limiter double that always says no; matches RateLimiter.check."""

    async def check(self, key: str, limit: int, window_seconds: int = 60) -> bool:
        return False


@pytest.fixture(autouse=True)
def _clean_secret_registry():
    clear_registry()
    yield
    clear_registry()


@pytest.fixture
def cipher(settings):
    return build_token_cipher(settings)


@pytest.fixture
def fake_google():
    return FakeGoogle()


@pytest.fixture
async def http_client(fake_google):
    client = httpx.AsyncClient(transport=httpx.MockTransport(fake_google.handler))
    yield client
    await client.aclose()


@pytest.fixture
def grant_cache(redis_client):
    return GrantCache(redis_client)


@pytest.fixture
def rate_limiter(redis_client):
    return RateLimiter(redis_client)


@pytest.fixture
def idempotency_store(redis_client, settings):
    return IdempotencyStore(redis_client, settings.idempotency_window_seconds)


@pytest.fixture
def service(
    settings, session_factory, cipher, grant_cache, rate_limiter, idempotency_store, http_client
):
    return InvokeService(
        settings=settings,
        session_factory=session_factory,
        cipher=cipher,
        grant_cache=grant_cache,
        rate_limiter=rate_limiter,
        idempotency_store=idempotency_store,
        http_client=http_client,
    )


@pytest.fixture
async def agent(session):
    agent = AgentIdentity(user_id=USER_ID, name="invoke-test-agent", allowed_scopes=["drive.read"])
    session.add(agent)
    await session.commit()
    return agent


@pytest.fixture
async def account(session, cipher):
    account = ConnectedAccount(
        user_id=USER_ID,
        provider="google",
        encrypted_access_token=cipher.encrypt(ACCESS_TOKEN),
        encrypted_refresh_token=cipher.encrypt(REFRESH_TOKEN),
        scopes_granted=["https://www.googleapis.com/auth/drive.readonly"],
        expires_at=utcnow() + timedelta(hours=1),
    )
    session.add(account)
    await session.commit()
    return account


async def issue_grant(session, settings, agent, grant_cache=None):
    return await request_grant(
        session=session,
        settings=settings,
        agent_id=agent.id,
        tool_name="drive.read",
        requested_scope="read",
        grant_cache=grant_cache,
    )


async def audit_rows(session) -> list[ToolCallAuditLog]:
    return list((await session.execute(select(ToolCallAuditLog))).scalars().all())


async def test_happy_path_success(session, settings, service, fake_google, agent, account):
    issued = await issue_grant(session, settings, agent)

    outcome = await service.invoke(
        grant_token=issued.token, tool_name="drive.read", arguments=ARGUMENTS
    )

    assert outcome.status == "success"
    assert outcome.result == DRIVE_RESULT
    assert outcome.error is None
    assert outcome.denied_reason is None
    assert outcome.from_cache is False
    assert isinstance(outcome.latency_ms, int) and outcome.latency_ms >= 0
    assert len(fake_google.drive_requests) == 1
    assert (
        fake_google.drive_requests[0].headers["authorization"] == f"Bearer {ACCESS_TOKEN}"
    )

    rows = await audit_rows(session)
    assert len(rows) == 1
    assert rows[0].grant_id == issued.grant.id
    assert rows[0].tool_name == "drive.read"
    assert rows[0].status == "success"
    assert rows[0].arguments_hash == hash_arguments(ARGUMENTS)
    assert rows[0].latency_ms == outcome.latency_ms


async def test_expired_grant_token_denied_without_audit(
    session, settings, service, fake_google, agent, account
):
    # Token-level expiry: the JWT itself has lapsed, so no grant row is
    # resolved and no audit row can be attributed.
    token = sign_grant_token(
        settings=settings,
        grant_id=uuid.uuid4(),
        agent_id=agent.id,
        tool_name="drive.read",
        scope="read",
        issued_at=utcnow() - timedelta(seconds=600),
        expires_at=utcnow() - timedelta(seconds=300),
    )

    outcome = await service.invoke(grant_token=token, tool_name="drive.read", arguments={})

    assert outcome.status == "denied"
    assert "expired" in outcome.error
    assert outcome.denied_reason == "expired"
    assert fake_google.drive_requests == []
    assert await audit_rows(session) == []


async def test_expired_grant_row_denied_and_audited(
    session, settings, service, fake_google, agent, account
):
    # DB-level expiry: the token still verifies but the row (source of
    # truth) has lapsed — e.g. clock skew or a shortened TTL after issuance.
    issued = await issue_grant(session, settings, agent)
    await session.execute(
        update(Grant)
        .where(Grant.id == issued.grant.id)
        .values(expires_at=utcnow() - timedelta(seconds=1))
    )
    await session.commit()

    outcome = await service.invoke(grant_token=issued.token, tool_name="drive.read", arguments={})

    assert outcome.status == "denied"
    assert "expired" in outcome.error
    assert outcome.denied_reason == "expired"
    assert fake_google.drive_requests == []
    rows = await audit_rows(session)
    assert [r.status for r in rows] == ["denied"]
    assert rows[0].grant_id == issued.grant.id


async def test_revoked_grant_denied_and_audited(
    session, settings, service, grant_cache, fake_google, agent, account
):
    issued = await issue_grant(session, settings, agent, grant_cache=grant_cache)
    await revoke_grant(session=session, grant_id=issued.grant.id, grant_cache=grant_cache)

    outcome = await service.invoke(grant_token=issued.token, tool_name="drive.read", arguments={})

    assert outcome.status == "denied"
    assert "revoked" in outcome.error
    assert outcome.denied_reason == "revoked"
    assert fake_google.drive_requests == []
    rows = await audit_rows(session)
    assert [r.status for r in rows] == ["denied"]


async def test_revoked_in_db_denied_even_on_cache_miss(
    session, settings, service, fake_google, agent, account
):
    # A Redis flush (empty cache) must never resurrect a revoked grant: the
    # database revoked_at column is the source of truth.
    issued = await issue_grant(session, settings, agent)
    await revoke_grant(session=session, grant_id=issued.grant.id, grant_cache=None)

    outcome = await service.invoke(grant_token=issued.token, tool_name="drive.read", arguments={})

    assert outcome.status == "denied"
    assert "revoked" in outcome.error
    assert outcome.denied_reason == "revoked"
    assert fake_google.drive_requests == []


async def test_tool_name_mismatch_denied_without_audit(
    session, settings, service, fake_google, agent, account
):
    issued = await issue_grant(session, settings, agent)

    outcome = await service.invoke(
        grant_token=issued.token, tool_name="drive.write", arguments={}
    )

    assert outcome.status == "denied"
    assert "not valid for this tool" in outcome.error
    assert outcome.denied_reason == "tool_mismatch"
    assert fake_google.drive_requests == []
    assert await audit_rows(session) == []


async def test_grant_scope_tampering_denied_and_audited(
    session, settings, service, fake_google, agent, account
):
    issued = await issue_grant(session, settings, agent)
    await session.execute(
        update(Grant).where(Grant.id == issued.grant.id).values(scope="write")
    )
    await session.commit()

    outcome = await service.invoke(grant_token=issued.token, tool_name="drive.read", arguments={})

    assert outcome.status == "denied"
    assert "scope" in outcome.error
    assert outcome.denied_reason == "scope_mismatch"
    assert fake_google.drive_requests == []
    rows = await audit_rows(session)
    assert [r.status for r in rows] == ["denied"]


async def test_valid_signature_but_unknown_grant_denied_without_audit(
    session, settings, service, fake_google, agent, account
):
    token = sign_grant_token(
        settings=settings,
        grant_id=uuid.uuid4(),  # no such row
        agent_id=agent.id,
        tool_name="drive.read",
        scope="read",
        issued_at=utcnow(),
        expires_at=utcnow() + timedelta(seconds=300),
    )

    outcome = await service.invoke(grant_token=token, tool_name="drive.read", arguments={})

    assert outcome.status == "denied"
    assert "not found" in outcome.error
    assert outcome.denied_reason == "not_found"
    assert fake_google.drive_requests == []
    assert await audit_rows(session) == []


async def test_rate_limited_denied_and_audited(
    session, settings, session_factory, cipher, http_client, fake_google, agent, account
):
    issued = await issue_grant(session, settings, agent)
    service = InvokeService(
        settings=settings,
        session_factory=session_factory,
        cipher=cipher,
        rate_limiter=DenyAllRateLimiter(),
        http_client=http_client,
    )

    outcome = await service.invoke(grant_token=issued.token, tool_name="drive.read", arguments={})

    assert outcome.status == "denied"
    assert "rate limit" in outcome.error
    assert outcome.denied_reason == "rate_limited"
    assert fake_google.drive_requests == []
    rows = await audit_rows(session)
    assert [r.status for r in rows] == ["denied"]


async def test_provider_500_retried_then_failed(
    session, settings, service, fake_google, agent, account
):
    issued = await issue_grant(session, settings, agent)
    fake_google.drive_status = 500

    outcome = await service.invoke(grant_token=issued.token, tool_name="drive.read", arguments={})

    assert outcome.status == "failed"
    assert "500" in outcome.error
    assert outcome.result is None
    # One initial attempt plus every configured retry.
    assert len(fake_google.drive_requests) == settings.outbound_max_retries + 1
    rows = await audit_rows(session)
    assert [r.status for r in rows] == ["failed"]


async def test_provider_4xx_not_retried(session, settings, service, fake_google, agent, account):
    issued = await issue_grant(session, settings, agent)
    fake_google.drive_status = 403

    outcome = await service.invoke(grant_token=issued.token, tool_name="drive.read", arguments={})

    assert outcome.status == "failed"
    assert "403" in outcome.error
    assert len(fake_google.drive_requests) == 1
    rows = await audit_rows(session)
    assert [r.status for r in rows] == ["failed"]


async def test_idempotent_replay_serves_cache_without_provider_call(
    session, settings, service, fake_google, agent, account
):
    issued = await issue_grant(session, settings, agent)

    first = await service.invoke(
        grant_token=issued.token,
        tool_name="drive.read",
        arguments=ARGUMENTS,
        idempotency_key="job-42",
    )
    second = await service.invoke(
        grant_token=issued.token,
        tool_name="drive.read",
        arguments=ARGUMENTS,
        idempotency_key="job-42",
    )

    assert first.status == "success" and first.from_cache is False
    assert second.status == "success" and second.from_cache is True
    assert second.result == DRIVE_RESULT
    # The provider was hit exactly once; the replay came from the cache.
    assert len(fake_google.drive_requests) == 1
    rows = await audit_rows(session)
    assert sorted(r.status for r in rows) == ["success", "success"]


async def test_idempotency_conflict_denied(
    session, settings, service, idempotency_store, fake_google, agent, account
):
    issued = await issue_grant(session, settings, agent)
    # Another invocation holds the reservation mid-flight.
    assert await idempotency_store.reserve(f"{agent.id}:{account.id}:drive.read:job-7")

    outcome = await service.invoke(
        grant_token=issued.token,
        tool_name="drive.read",
        arguments={},
        idempotency_key="job-7",
    )

    assert outcome.status == "denied"
    assert "idempotency key" in outcome.error
    assert outcome.denied_reason == "idempotency_conflict"
    assert fake_google.drive_requests == []
    rows = await audit_rows(session)
    assert [r.status for r in rows] == ["denied"]


async def test_failed_call_releases_idempotency_reservation(
    session, settings, service, fake_google, agent, account
):
    issued = await issue_grant(session, settings, agent)
    fake_google.drive_status = 500

    failed = await service.invoke(
        grant_token=issued.token,
        tool_name="drive.read",
        arguments={},
        idempotency_key="job-9",
    )
    assert failed.status == "failed"

    fake_google.drive_status = 200
    retried = await service.invoke(
        grant_token=issued.token,
        tool_name="drive.read",
        arguments={},
        idempotency_key="job-9",
    )

    # The failed attempt must not wedge the key: the retry reaches the provider.
    assert retried.status == "success"
    assert retried.from_cache is False
    assert len(fake_google.drive_requests) == settings.outbound_max_retries + 1 + 1


async def test_refresh_path_when_account_expired(
    session, settings, service, cipher, fake_google, agent, account
):
    account.expires_at = utcnow() - timedelta(minutes=5)
    await session.commit()
    issued = await issue_grant(session, settings, agent)

    outcome = await service.invoke(grant_token=issued.token, tool_name="drive.read", arguments={})

    assert outcome.status == "success"
    assert len(fake_google.token_requests) == 1
    # The outbound call used the refreshed token, not the stale one.
    assert (
        fake_google.drive_requests[0].headers["authorization"]
        == f"Bearer {REFRESHED_ACCESS_TOKEN}"
    )
    await session.refresh(account)
    assert cipher.decrypt(account.encrypted_access_token) == REFRESHED_ACCESS_TOKEN
    # Google omitted refresh_token from the refresh response: keep the old one.
    assert cipher.decrypt(account.encrypted_refresh_token) == REFRESH_TOKEN
    assert ensure_aware(account.expires_at) > utcnow()
    rows = await audit_rows(session)
    assert [r.status for r in rows] == ["success"]


async def test_expired_account_without_refresh_token_fails(
    session, settings, service, cipher, fake_google, agent
):
    account = ConnectedAccount(
        user_id=USER_ID,
        provider="google",
        encrypted_access_token=cipher.encrypt(ACCESS_TOKEN),
        encrypted_refresh_token=None,
        scopes_granted=[],
        expires_at=utcnow() - timedelta(minutes=5),
    )
    session.add(account)
    await session.commit()
    issued = await issue_grant(session, settings, agent)

    outcome = await service.invoke(grant_token=issued.token, tool_name="drive.read", arguments={})

    assert outcome.status == "failed"
    assert "cannot be refreshed" in outcome.error
    assert fake_google.drive_requests == []
    assert fake_google.token_requests == []
    rows = await audit_rows(session)
    assert [r.status for r in rows] == ["failed"]


async def test_garbage_token_denied_without_audit(session, settings, service, fake_google):
    outcome = await service.invoke(
        grant_token="not-a-jwt", tool_name="drive.read", arguments={}
    )

    assert outcome.status == "denied"
    assert "invalid" in outcome.error
    assert outcome.denied_reason == "invalid_token"
    assert fake_google.drive_requests == []
    assert await audit_rows(session) == []


async def test_transport_error_during_refresh_failed_audited_without_raw_text(
    session, settings, service, fake_google, agent, account
):
    account.expires_at = utcnow() - timedelta(minutes=5)
    await session.commit()
    fake_google.token_error = httpx.ConnectError(
        "connect boom at https://oauth2.googleapis.com/token"
    )
    issued = await issue_grant(session, settings, agent)

    outcome = await service.invoke(grant_token=issued.token, tool_name="drive.read", arguments={})

    assert outcome.status == "failed"
    assert "credential refresh failed" in outcome.error
    # The transport error's own text (URLs, hosts) must never reach the agent.
    assert "boom" not in outcome.error
    assert "oauth2.googleapis.com" not in outcome.error
    assert fake_google.drive_requests == []
    rows = await audit_rows(session)
    assert [r.status for r in rows] == ["failed"]


async def test_idempotency_key_is_isolated_per_connected_account(
    session, settings, service, cipher, idempotency_store, fake_google, agent, account
):
    issued_a = await issue_grant(session, settings, agent)
    first = await service.invoke(
        grant_token=issued_a.token,
        tool_name="drive.read",
        arguments=ARGUMENTS,
        idempotency_key="job-77",
    )
    assert first.status == "success" and first.from_cache is False
    # The cache key is bound to the connected account, not just the agent.
    cached = await idempotency_store.get(f"{agent.id}:{account.id}:drive.read:job-77")
    assert cached == DRIVE_RESULT

    account_b = ConnectedAccount(
        user_id=USER_ID,
        provider="google",
        encrypted_access_token=cipher.encrypt(ACCESS_TOKEN),
        encrypted_refresh_token=cipher.encrypt(REFRESH_TOKEN),
        scopes_granted=["https://www.googleapis.com/auth/drive.readonly"],
        expires_at=utcnow() + timedelta(hours=1),
        # Strictly newest so grant issuance binds to this account.
        created_at=utcnow() + timedelta(seconds=5),
    )
    session.add(account_b)
    await session.commit()
    # Free the agent's active-grant slot; the idempotency cache entry is
    # keyed by agent + account, not by grant, so it survives the revocation.
    await revoke_grant(session=session, grant_id=issued_a.grant.id, grant_cache=None)
    issued_b = await issue_grant(session, settings, agent)
    assert issued_b.grant.connected_account_id == account_b.id

    second = await service.invoke(
        grant_token=issued_b.token,
        tool_name="drive.read",
        arguments=ARGUMENTS,
        idempotency_key="job-77",
    )

    # Same agent, same key, different account: the result cached against
    # account A must not be replayed — the provider is called again.
    assert second.status == "success" and second.from_cache is False
    assert len(fake_google.drive_requests) == 2


async def test_provider_401_triggers_one_refresh_and_retry(
    session, settings, service, cipher, fake_google, agent, account
):
    issued = await issue_grant(session, settings, agent)
    # The stored token looks fresh but the provider rejects it (invalidated
    # server-side); only a refresh can recover.
    fake_google.reject_bearer = ACCESS_TOKEN

    outcome = await service.invoke(grant_token=issued.token, tool_name="drive.read", arguments={})

    assert outcome.status == "success"
    assert len(fake_google.token_requests) == 1
    assert len(fake_google.drive_requests) == 2
    assert fake_google.drive_requests[0].headers["authorization"] == f"Bearer {ACCESS_TOKEN}"
    assert (
        fake_google.drive_requests[1].headers["authorization"]
        == f"Bearer {REFRESHED_ACCESS_TOKEN}"
    )
    # The rotated credential was persisted, not just used once.
    await session.refresh(account)
    assert cipher.decrypt(account.encrypted_access_token) == REFRESHED_ACCESS_TOKEN
    rows = await audit_rows(session)
    assert [r.status for r in rows] == ["success"]


async def test_provider_401_after_refresh_fails_without_looping(
    session, settings, service, fake_google, agent, account
):
    issued = await issue_grant(session, settings, agent)
    fake_google.drive_status = 401  # every token is rejected

    outcome = await service.invoke(grant_token=issued.token, tool_name="drive.read", arguments={})

    assert outcome.status == "failed"
    assert "401" in outcome.error
    # Exactly one refresh and one retry: no refresh loop.
    assert len(fake_google.token_requests) == 1
    assert len(fake_google.drive_requests) == 2
    rows = await audit_rows(session)
    assert [r.status for r in rows] == ["failed"]


async def test_account_expiring_within_margin_is_refreshed_proactively(
    session, settings, service, fake_google, agent, account
):
    # 30s from expiry: inside the refresh margin, though not yet expired.
    account.expires_at = utcnow() + timedelta(seconds=30)
    await session.commit()
    issued = await issue_grant(session, settings, agent)

    outcome = await service.invoke(grant_token=issued.token, tool_name="drive.read", arguments={})

    assert outcome.status == "success"
    assert len(fake_google.token_requests) == 1
    assert (
        fake_google.drive_requests[0].headers["authorization"]
        == f"Bearer {REFRESHED_ACCESS_TOKEN}"
    )


async def test_account_within_margin_but_unrefreshable_still_uses_stored_token(
    session, settings, service, cipher, fake_google, agent
):
    account = ConnectedAccount(
        user_id=USER_ID,
        provider="google",
        encrypted_access_token=cipher.encrypt(ACCESS_TOKEN),
        encrypted_refresh_token=None,
        scopes_granted=[],
        expires_at=utcnow() + timedelta(seconds=30),
    )
    session.add(account)
    await session.commit()
    issued = await issue_grant(session, settings, agent)

    outcome = await service.invoke(grant_token=issued.token, tool_name="drive.read", arguments={})

    # No refresh token, but the stored credential is still valid: use it.
    assert outcome.status == "success"
    assert fake_google.token_requests == []
    assert fake_google.drive_requests[0].headers["authorization"] == f"Bearer {ACCESS_TOKEN}"


async def test_unexpected_exception_is_audited_with_generic_error(
    session, settings, service, fake_google, agent, account, caplog
):
    issued = await issue_grant(session, settings, agent)
    fake_google.drive_error = RuntimeError(f"exploded while holding {ACCESS_TOKEN}")

    with caplog.at_level(logging.ERROR):
        outcome = await service.invoke(
            grant_token=issued.token, tool_name="drive.read", arguments={}
        )

    assert outcome.status == "failed"
    assert outcome.error == "internal error during tool invocation"
    rows = await audit_rows(session)
    assert [r.status for r in rows] == ["failed"]
    # Server-side, the log names the exception type but scrubs the secret.
    assert "RuntimeError" in caplog.text
    assert ACCESS_TOKEN not in caplog.text


async def test_owned_http_client_created_lazily_and_closed(settings, session_factory, cipher):
    service = InvokeService(settings=settings, session_factory=session_factory, cipher=cipher)

    client = service._http()

    assert isinstance(client, httpx.AsyncClient)
    assert client.timeout == httpx.Timeout(15.0)
    assert service._http() is client  # created once, then reused
    await service.aclose()
    assert client.is_closed


async def test_injected_http_client_is_not_closed_by_aclose(
    settings, session_factory, cipher, http_client
):
    service = InvokeService(
        settings=settings, session_factory=session_factory, cipher=cipher, http_client=http_client
    )

    await service.aclose()

    assert not http_client.is_closed
