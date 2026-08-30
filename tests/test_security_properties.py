"""Security-property regression tests for the whole broker.

These tests pin the invariants the project exists to provide:

1. A raw provider credential (access or refresh token) never appears in any
   log line, any invoke outcome field, any audit row, or anywhere in the
   database in plaintext — even when a log statement deliberately tries to
   print it (the redaction filter must scrub it).
2. The grants table stores only the SHA-256 hash of a grant token, never the
   token itself.
3. A revoked grant is denied immediately — including a revocation that lands
   mid-flight, after the initial checks but before the outbound provider
   call — and the denial is audited.
4. An expired grant token is denied without reaching the provider.

Everything runs against SQLite, fakeredis, and an httpx.MockTransport; a
real logging handler with the production SecretRedactionFilter captures all
log output to a StringIO for inspection.
"""

import io
import json
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
    utcnow,
)
from credbroker.grants.service import request_grant, revoke_grant
from credbroker.grants.tokens import hash_token, sign_grant_token
from credbroker.invoke.service import InvokeService
from credbroker.logging_config import REDACTED, SecretRedactionFilter, clear_registry
from credbroker.reliability.idempotency import IdempotencyStore

ACCESS_TOKEN = "ya29.super-secret-live-access-token-000111222333"
# One user owns both the agent and the connected account in these tests.
USER_ID = uuid.uuid4()
REFRESH_TOKEN = "1//super-secret-live-refresh-token-444555666777"

DRIVE_RESULT = {"files": [{"id": "f1", "name": "quarterly-report.pdf"}]}
ARGUMENTS = {"query": "name contains 'report'"}


class FakeDrive:
    """MockTransport handler for the Drive API, counting hits."""

    def __init__(self):
        self.requests: list[httpx.Request] = []
        # When set, requests raise this instead of answering.
        self.error: Exception | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return httpx.Response(200, json=DRIVE_RESULT)


class CacheRevokingRateLimiter:
    """Rate limiter double that revokes the grant mid-flight via Redis.

    The revocation marker lands after the invoke path's initial revocation
    checks have already passed (the limiter runs at step 4), so only the
    pre-outbound re-check can catch it.
    """

    def __init__(self, grant_cache: GrantCache, token_hash: str):
        self._grant_cache = grant_cache
        self._token_hash = token_hash

    async def check(self, key: str, limit: int, window_seconds: int = 60) -> bool:
        await self._grant_cache.record_revoked(self._token_hash)
        return True


class DbRevokingRateLimiter:
    """Rate limiter double that revokes the grant mid-flight in the database.

    With no Redis cache configured, the pre-outbound re-check must fall back
    to a fresh read of ``grants.revoked_at`` — the source of truth.
    """

    def __init__(self, session_factory, grant_id: uuid.UUID):
        self._session_factory = session_factory
        self._grant_id = grant_id

    async def check(self, key: str, limit: int, window_seconds: int = 60) -> bool:
        async with self._session_factory() as session:
            await session.execute(
                update(Grant).where(Grant.id == self._grant_id).values(revoked_at=utcnow())
            )
            await session.commit()
        return True


@pytest.fixture(autouse=True)
def _clean_secret_registry():
    clear_registry()
    yield
    clear_registry()


@pytest.fixture
def log_capture():
    """Attach a real handler + SecretRedactionFilter capturing every log line."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setLevel(logging.DEBUG)
    handler.addFilter(SecretRedactionFilter())
    root = logging.getLogger()
    previous_level = root.level
    root.setLevel(logging.DEBUG)
    root.addHandler(handler)
    yield stream
    root.removeHandler(handler)
    root.setLevel(previous_level)


@pytest.fixture
def cipher(settings):
    return build_token_cipher(settings)


@pytest.fixture
def fake_drive():
    return FakeDrive()


@pytest.fixture
async def http_client(fake_drive):
    client = httpx.AsyncClient(transport=httpx.MockTransport(fake_drive.handler))
    yield client
    await client.aclose()


@pytest.fixture
def grant_cache(redis_client):
    return GrantCache(redis_client)


@pytest.fixture
def service(settings, session_factory, cipher, grant_cache, redis_client, http_client):
    return InvokeService(
        settings=settings,
        session_factory=session_factory,
        cipher=cipher,
        grant_cache=grant_cache,
        rate_limiter=RateLimiter(redis_client),
        idempotency_store=IdempotencyStore(redis_client, settings.idempotency_window_seconds),
        http_client=http_client,
    )


@pytest.fixture
async def agent(session):
    agent = AgentIdentity(user_id=USER_ID, name="security-test-agent", allowed_scopes=["drive.read"])
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


async def all_db_content(session) -> tuple[str, list[bytes]]:
    """Every column of every row: text fields joined, byte blobs listed."""
    text_parts: list[str] = []
    blobs: list[bytes] = []
    for model in (ConnectedAccount, AgentIdentity, Grant, ToolCallAuditLog):
        for row in (await session.execute(select(model))).scalars():
            for column in model.__table__.columns:
                value = getattr(row, column.name)
                if isinstance(value, bytes):
                    blobs.append(value)
                elif value is not None:
                    text_parts.append(str(value))
    return "\n".join(text_parts), blobs


async def test_raw_token_never_in_logs_outcome_audit_or_db(
    session, settings, service, log_capture, fake_drive, agent, account
):
    issued = await issue_grant(session, settings, agent)

    # A deliberately leaky log statement: the redaction filter must scrub the
    # registered credential rather than rely on nobody ever logging it.
    logging.getLogger("security.test.leak").info("access token is %s", ACCESS_TOKEN)

    outcome = await service.invoke(
        grant_token=issued.token, tool_name="drive.read", arguments=ARGUMENTS
    )
    assert outcome.status == "success"
    assert outcome.result == DRIVE_RESULT

    # 1. No log line carries either raw credential; the leaky line was
    #    rewritten to the redaction marker, not silently dropped.
    logs = log_capture.getvalue()
    assert ACCESS_TOKEN not in logs
    assert REFRESH_TOKEN not in logs
    assert REDACTED in logs

    # 2. No outcome field carries a credential.
    outcome_text = json.dumps(outcome.result) + (outcome.error or "") + outcome.status
    assert ACCESS_TOKEN not in outcome_text
    assert REFRESH_TOKEN not in outcome_text

    # 3. Exactly one audit row, and no audit field carries a credential.
    audit = list((await session.execute(select(ToolCallAuditLog))).scalars().all())
    assert len(audit) == 1
    assert audit[0].status == "success"
    audit_text = " ".join(
        str(getattr(audit[0], c.name)) for c in ToolCallAuditLog.__table__.columns
    )
    assert ACCESS_TOKEN not in audit_text
    assert REFRESH_TOKEN not in audit_text

    # 4. Nowhere in the database does a credential exist in plaintext —
    #    including inside the encrypted blobs themselves.
    db_text, blobs = await all_db_content(session)
    assert ACCESS_TOKEN not in db_text
    assert REFRESH_TOKEN not in db_text
    assert len(blobs) >= 2
    for blob in blobs:
        assert ACCESS_TOKEN.encode() not in blob
        assert REFRESH_TOKEN.encode() not in blob


async def test_grants_table_stores_only_token_hash(session, settings, agent, account):
    issued = await issue_grant(session, settings, agent)

    row = (await session.execute(select(Grant))).scalar_one()
    assert row.grant_token_hash == hash_token(issued.token)

    db_text, _ = await all_db_content(session)
    assert issued.token not in db_text
    assert hash_token(issued.token) in db_text


async def test_invoke_after_revoke_is_denied_and_audited(
    session, settings, service, grant_cache, fake_drive, agent, account
):
    issued = await issue_grant(session, settings, agent, grant_cache=grant_cache)

    first = await service.invoke(
        grant_token=issued.token, tool_name="drive.read", arguments=ARGUMENTS
    )
    assert first.status == "success"
    assert len(fake_drive.requests) == 1

    await revoke_grant(session=session, grant_id=issued.grant.id, grant_cache=grant_cache)

    denied = await service.invoke(
        grant_token=issued.token, tool_name="drive.read", arguments=ARGUMENTS
    )
    assert denied.status == "denied"
    assert "revoked" in denied.error
    # The provider was not contacted again.
    assert len(fake_drive.requests) == 1

    audit = list((await session.execute(select(ToolCallAuditLog))).scalars().all())
    assert sorted(r.status for r in audit) == ["denied", "success"]
    assert all(r.grant_id == issued.grant.id for r in audit)


async def test_mid_flight_revocation_via_cache_aborts_before_outbound(
    session, settings, session_factory, cipher, grant_cache, http_client, fake_drive,
    agent, account,
):
    issued = await issue_grant(session, settings, agent, grant_cache=grant_cache)
    # The limiter runs after the initial revocation checks; it plants the
    # revocation marker so only the pre-outbound re-check can see it.
    service = InvokeService(
        settings=settings,
        session_factory=session_factory,
        cipher=cipher,
        grant_cache=grant_cache,
        rate_limiter=CacheRevokingRateLimiter(grant_cache, hash_token(issued.token)),
        http_client=http_client,
    )

    outcome = await service.invoke(
        grant_token=issued.token, tool_name="drive.read", arguments=ARGUMENTS
    )

    assert outcome.status == "denied"
    assert "revoked" in outcome.error
    # The credential was never used: the provider was not contacted.
    assert fake_drive.requests == []
    audit = list((await session.execute(select(ToolCallAuditLog))).scalars().all())
    assert [r.status for r in audit] == ["denied"]


async def test_mid_flight_revocation_via_db_aborts_before_outbound(
    session, settings, session_factory, cipher, http_client, fake_drive, agent, account
):
    issued = await issue_grant(session, settings, agent)
    # No Redis cache at all: the pre-outbound re-check must read the fresh
    # revoked_at column from the database, the source of truth.
    service = InvokeService(
        settings=settings,
        session_factory=session_factory,
        cipher=cipher,
        grant_cache=None,
        rate_limiter=DbRevokingRateLimiter(session_factory, issued.grant.id),
        http_client=http_client,
    )

    outcome = await service.invoke(
        grant_token=issued.token, tool_name="drive.read", arguments=ARGUMENTS
    )

    assert outcome.status == "denied"
    assert "revoked" in outcome.error
    assert fake_drive.requests == []
    audit = list((await session.execute(select(ToolCallAuditLog))).scalars().all())
    assert [r.status for r in audit] == ["denied"]


async def test_expired_grant_token_denied_without_provider_contact(
    session, settings, service, fake_drive, agent, account
):
    expired_token = sign_grant_token(
        settings=settings,
        grant_id=uuid.uuid4(),
        agent_id=agent.id,
        tool_name="drive.read",
        scope="read",
        issued_at=utcnow() - timedelta(minutes=20),
        expires_at=utcnow() - timedelta(minutes=10),
    )

    outcome = await service.invoke(
        grant_token=expired_token, tool_name="drive.read", arguments=ARGUMENTS
    )

    assert outcome.status == "denied"
    assert "expired" in outcome.error
    assert fake_drive.requests == []


async def test_unexpected_exception_is_generic_audited_and_leak_free(
    session, settings, service, log_capture, fake_drive, agent, account
):
    # An exception type the invoke path never anticipated, deliberately
    # carrying a raw credential in its message: it must become a generic,
    # audited failure — str(exc) reaches neither the agent nor (unscrubbed)
    # the logs.
    issued = await issue_grant(session, settings, agent)
    fake_drive.error = RuntimeError(f"exploded while holding {ACCESS_TOKEN}")

    outcome = await service.invoke(
        grant_token=issued.token, tool_name="drive.read", arguments=ARGUMENTS
    )

    assert outcome.status == "failed"
    assert ACCESS_TOKEN not in outcome.error
    assert "exploded" not in outcome.error  # generic message, not str(exc)

    logs = log_capture.getvalue()
    assert ACCESS_TOKEN not in logs
    assert REFRESH_TOKEN not in logs

    audit = list((await session.execute(select(ToolCallAuditLog))).scalars().all())
    assert [r.status for r in audit] == ["failed"]
    assert audit[0].grant_id == issued.grant.id


async def test_tampered_grant_token_denied(session, settings, service, fake_drive, agent, account):
    issued = await issue_grant(session, settings, agent)
    header, payload, signature = issued.token.split(".")
    tampered = f"{header}.{payload}.{signature[:-4]}AAAA"

    outcome = await service.invoke(
        grant_token=tampered, tool_name="drive.read", arguments=ARGUMENTS
    )

    assert outcome.status == "denied"
    assert fake_drive.requests == []
