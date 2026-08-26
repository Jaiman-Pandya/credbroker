"""Tests for the invoke path (credbroker.invoke.service).

Everything runs against SQLite and an httpx.MockTransport that plays both
the Google Drive API and the OAuth token endpoint — no network.
"""

import logging
import uuid
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import update

from credbroker.crypto.kms import build_token_cipher
from credbroker.db.models import (
    AgentIdentity,
    ConnectedAccount,
    Grant,
    ensure_aware,
    utcnow,
)
from credbroker.grants.service import request_grant, revoke_grant
from credbroker.grants.tokens import sign_grant_token
from credbroker.invoke.service import InvokeService
from credbroker.logging_config import clear_registry

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
def service(settings, session_factory, cipher, http_client):
    return InvokeService(
        settings=settings,
        session_factory=session_factory,
        cipher=cipher,
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


async def issue_grant(session, settings, agent):
    return await request_grant(
        session=session,
        settings=settings,
        agent_id=agent.id,
        tool_name="drive.read",
        requested_scope="read",
    )


async def test_happy_path_success(session, settings, service, fake_google, agent, account):
    issued = await issue_grant(session, settings, agent)

    outcome = await service.invoke(
        grant_token=issued.token, tool_name="drive.read", arguments=ARGUMENTS
    )

    assert outcome.status == "success"
    assert outcome.result == DRIVE_RESULT
    assert outcome.error is None
    assert outcome.denied_reason is None
    assert isinstance(outcome.latency_ms, int) and outcome.latency_ms >= 0
    assert len(fake_google.drive_requests) == 1
    assert (
        fake_google.drive_requests[0].headers["authorization"] == f"Bearer {ACCESS_TOKEN}"
    )


async def test_expired_grant_token_denied(
    session, settings, service, fake_google, agent, account
):
    # Token-level expiry: the JWT itself has lapsed, so no grant row is
    # ever resolved.
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


async def test_expired_grant_row_denied(
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


async def test_revoked_grant_denied(
    session, settings, service, fake_google, agent, account
):
    issued = await issue_grant(session, settings, agent)
    await revoke_grant(session=session, grant_id=issued.grant.id)

    outcome = await service.invoke(grant_token=issued.token, tool_name="drive.read", arguments={})

    assert outcome.status == "denied"
    assert "revoked" in outcome.error
    assert outcome.denied_reason == "revoked"
    assert fake_google.drive_requests == []


async def test_tool_name_mismatch_denied(
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


async def test_grant_scope_tampering_denied(
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


async def test_valid_signature_but_unknown_grant_denied(
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


async def test_provider_500_reported_as_failed(
    session, settings, service, fake_google, agent, account
):
    issued = await issue_grant(session, settings, agent)
    fake_google.drive_status = 500

    outcome = await service.invoke(grant_token=issued.token, tool_name="drive.read", arguments={})

    assert outcome.status == "failed"
    assert "500" in outcome.error
    assert outcome.result is None
    assert len(fake_google.drive_requests) == 1


async def test_provider_4xx_reported_as_failed(
    session, settings, service, fake_google, agent, account
):
    issued = await issue_grant(session, settings, agent)
    fake_google.drive_status = 403

    outcome = await service.invoke(grant_token=issued.token, tool_name="drive.read", arguments={})

    assert outcome.status == "failed"
    assert "403" in outcome.error
    assert len(fake_google.drive_requests) == 1


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


async def test_garbage_token_denied(session, settings, service, fake_google):
    outcome = await service.invoke(
        grant_token="not-a-jwt", tool_name="drive.read", arguments={}
    )

    assert outcome.status == "denied"
    assert "invalid" in outcome.error
    assert outcome.denied_reason == "invalid_token"
    assert fake_google.drive_requests == []


async def test_transport_error_during_refresh_failed_without_raw_text(
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


async def test_unexpected_exception_reported_with_generic_error(
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
