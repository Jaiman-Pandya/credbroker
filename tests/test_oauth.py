"""Tests for the Google OAuth connect flow.

The token endpoint is faked with httpx.MockTransport; the app is driven
through httpx.ASGITransport against create_app. The cipher is a duck-typed
fake — real envelope encryption is covered by the crypto component's tests;
here we assert the router encrypts *through* the cipher and that raw tokens
never surface in responses, rows, or log-scrubbable text.
"""

import base64
import uuid
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from prometheus_client import REGISTRY
from sqlalchemy import select

from credbroker import logging_config
from credbroker.app import create_app
from credbroker.db.models import ConnectedAccount, ensure_aware, utcnow
from credbroker.errors import OAuthFlowError
from credbroker.oauth import google
from credbroker.oauth.state import make_state, verify_state

ACCESS_TOKEN = "ya29.test-access-token-abcdef-123456"
REFRESH_TOKEN = "1//test-refresh-token-abcdef-123456"
DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.readonly"


class FakeCipher:
    """Duck-typed stand-in for crypto.kms.TokenCipher (tested in its own suite)."""

    def encrypt(self, plaintext: str) -> bytes:
        return b"enc1:" + base64.b64encode(plaintext.encode())

    def decrypt(self, blob: bytes) -> str:
        assert blob.startswith(b"enc1:")
        return base64.b64decode(blob[len(b"enc1:") :]).decode()


class FakeGoogle:
    """Records token-endpoint requests and serves a configurable response."""

    def __init__(self):
        self.calls: list[httpx.Request] = []
        self.status_code = 200
        self.text: str | None = None  # overrides payload when set (non-JSON bodies)
        self.payload: dict = {
            "access_token": ACCESS_TOKEN,
            "refresh_token": REFRESH_TOKEN,
            "expires_in": 3600,
            "scope": DRIVE_SCOPE,
            "token_type": "Bearer",
        }

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert str(request.url) == google.GOOGLE_TOKEN_URL
        self.calls.append(request)
        if self.text is not None:
            return httpx.Response(self.status_code, text=self.text)
        return httpx.Response(self.status_code, json=self.payload)


@pytest.fixture(autouse=True)
def _clean_secret_registry():
    logging_config.clear_registry()
    yield
    logging_config.clear_registry()


@pytest.fixture
def fake_google():
    return FakeGoogle()


@pytest.fixture
async def http_client(fake_google):
    transport = httpx.MockTransport(fake_google.handler)
    async with httpx.AsyncClient(transport=transport) as client:
        yield client


@pytest.fixture
def cipher():
    return FakeCipher()


@pytest.fixture
def app(settings, session_factory, cipher, http_client):
    return create_app(
        settings=settings,
        session_factory=session_factory,
        cipher=cipher,
        http_client=http_client,
    )


@pytest.fixture
async def client(app):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


def _form(request: httpx.Request) -> dict[str, str]:
    """Decode an application/x-www-form-urlencoded request body."""
    return {k: v[0] for k, v in parse_qs(request.content.decode()).items()}


# ---------------------------------------------------------------------------
# state.py


def test_state_roundtrip(settings):
    user_id = str(uuid.uuid4())
    state = make_state(settings, user_id)
    assert verify_state(settings, state) == user_id


def test_state_is_unique_per_mint(settings):
    user_id = str(uuid.uuid4())
    assert make_state(settings, user_id) != make_state(settings, user_id)


def test_state_tampered_payload_rejected(settings):
    state = make_state(settings, str(uuid.uuid4()))
    decoded = base64.urlsafe_b64decode(state.encode()).decode()
    parts = decoded.split("|")
    parts[0] = str(uuid.uuid4())  # swap in a different user id, keep the signature
    forged = base64.urlsafe_b64encode("|".join(parts).encode()).decode()
    with pytest.raises(OAuthFlowError):
        verify_state(settings, forged)


def test_state_wrong_secret_rejected(settings):
    state = make_state(settings, str(uuid.uuid4()))
    other = settings.model_copy(update={"oauth_state_secret": "a-completely-different-secret"})
    with pytest.raises(OAuthFlowError):
        verify_state(other, state)


def test_state_garbage_rejected(settings):
    for garbage in ["", "!!!not-base64!!!", base64.urlsafe_b64encode(b"a|b").decode()]:
        with pytest.raises(OAuthFlowError):
            verify_state(settings, garbage)


def test_state_expired_rejected(settings):
    expired_minter = settings.model_copy(update={"oauth_state_ttl_seconds": -1})
    state = make_state(expired_minter, str(uuid.uuid4()))
    with pytest.raises(OAuthFlowError, match="expired"):
        verify_state(settings, state)


# ---------------------------------------------------------------------------
# google.py


async def test_exchange_code_sends_correct_form(settings, http_client, fake_google):
    token = await google.exchange_code(http_client, settings, "auth-code-123")

    assert len(fake_google.calls) == 1
    form = _form(fake_google.calls[0])
    assert form == {
        "client_id": "test-client-id",
        "client_secret": "test-client-secret",
        "code": "auth-code-123",
        "grant_type": "authorization_code",
        "redirect_uri": f"{settings.public_base_url}/oauth/google/callback",
    }
    assert token.access_token == ACCESS_TOKEN
    assert token.refresh_token == REFRESH_TOKEN
    assert token.expires_in == 3600
    assert token.scopes == [DRIVE_SCOPE]


async def test_exchange_code_registers_secrets_for_redaction(settings, http_client):
    await google.exchange_code(http_client, settings, "auth-code-123")
    scrubbed = logging_config.scrub(f"leak {ACCESS_TOKEN} and {REFRESH_TOKEN}")
    assert ACCESS_TOKEN not in scrubbed
    assert REFRESH_TOKEN not in scrubbed


async def test_exchange_code_error_hides_response_body(settings, http_client, fake_google):
    fake_google.status_code = 400
    fake_google.text = '{"error": "invalid_grant", "echo": "auth-code-123 test-client-secret"}'
    with pytest.raises(OAuthFlowError) as excinfo:
        await google.exchange_code(http_client, settings, "auth-code-123")
    message = str(excinfo.value)
    assert "400" in message
    assert "auth-code-123" not in message
    assert "test-client-secret" not in message
    assert "invalid_grant" not in message


async def test_exchange_code_non_json_success_rejected(settings, http_client, fake_google):
    fake_google.text = "<html>proxy error</html>"
    with pytest.raises(OAuthFlowError):
        await google.exchange_code(http_client, settings, "auth-code-123")


async def test_refresh_access_token(settings, http_client, fake_google):
    # Google refresh responses normally omit refresh_token.
    fake_google.payload = {
        "access_token": "ya29.refreshed-access-token-9876",
        "expires_in": 3599,
        "scope": DRIVE_SCOPE,
        "token_type": "Bearer",
    }
    token = await google.refresh_access_token(http_client, settings, "stored-refresh-token")

    form = _form(fake_google.calls[0])
    assert form["grant_type"] == "refresh_token"
    assert form["refresh_token"] == "stored-refresh-token"
    assert token.access_token == "ya29.refreshed-access-token-9876"
    assert token.refresh_token is None
    assert "ya29.refreshed-access-token-9876" not in logging_config.scrub(
        "x ya29.refreshed-access-token-9876 x"
    )


def test_build_authorize_url(settings):
    url = google.build_authorize_url(settings, "the-state")
    parsed = urlparse(url)
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == google.GOOGLE_AUTH_URL
    query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    assert query["client_id"] == "test-client-id"
    assert query["redirect_uri"] == f"{settings.public_base_url}/oauth/google/callback"
    assert query["response_type"] == "code"
    assert query["scope"] == DRIVE_SCOPE
    assert query["state"] == "the-state"
    assert query["access_type"] == "offline"


# ---------------------------------------------------------------------------
# router: /oauth/{provider}/authorize


async def test_authorize_redirects_to_google(client, settings):
    user_id = uuid.uuid4()
    response = await client.get(f"/oauth/google/authorize?user_id={user_id}")

    assert response.status_code == 307
    location = response.headers["location"]
    parsed = urlparse(location)
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == google.GOOGLE_AUTH_URL
    query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    assert verify_state(settings, query["state"]) == str(user_id)


async def test_authorize_unknown_provider_404(client):
    response = await client.get(f"/oauth/slack/authorize?user_id={uuid.uuid4()}")
    assert response.status_code == 404


async def test_authorize_missing_user_id_422(client):
    response = await client.get("/oauth/google/authorize")
    assert response.status_code == 422


async def test_authorize_invalid_user_id_422(client):
    response = await client.get("/oauth/google/authorize?user_id=not-a-uuid")
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# router: /oauth/{provider}/callback


async def test_callback_stores_encrypted_account(
    client, settings, session, fake_google, cipher
):
    user_id = uuid.uuid4()
    state = make_state(settings, str(user_id))
    before = (
        REGISTRY.get_sample_value(
            "credbroker_accounts_connected_total", {"provider": "google"}
        )
        or 0.0
    )

    response = await client.get(
        f"/oauth/google/callback?code=auth-code-123&state={state}"
    )

    assert response.status_code == 200
    body = response.json()
    assert body["provider"] == "google"
    assert body["scopes"] == [DRIVE_SCOPE]
    account_id = uuid.UUID(body["connected_account_id"])

    # The response must never contain raw tokens.
    assert ACCESS_TOKEN not in response.text
    assert REFRESH_TOKEN not in response.text

    # The provider was called exactly once with our code.
    assert len(fake_google.calls) == 1
    assert _form(fake_google.calls[0])["code"] == "auth-code-123"

    row = (
        await session.execute(
            select(ConnectedAccount).where(ConnectedAccount.id == account_id)
        )
    ).scalar_one()
    assert row.user_id == user_id
    assert row.provider == "google"
    assert row.scopes_granted == [DRIVE_SCOPE]

    # Tokens are stored encrypted: not the plaintext, not containing it.
    assert row.encrypted_access_token != ACCESS_TOKEN.encode()
    assert ACCESS_TOKEN.encode() not in row.encrypted_access_token
    assert cipher.decrypt(row.encrypted_access_token) == ACCESS_TOKEN
    assert row.encrypted_refresh_token is not None
    assert REFRESH_TOKEN.encode() not in row.encrypted_refresh_token
    assert cipher.decrypt(row.encrypted_refresh_token) == REFRESH_TOKEN

    expires_at = ensure_aware(row.expires_at)
    assert utcnow() + timedelta(seconds=3500) < expires_at < utcnow() + timedelta(seconds=3700)

    after = REGISTRY.get_sample_value(
        "credbroker_accounts_connected_total", {"provider": "google"}
    )
    assert after == before + 1.0


async def test_callback_without_refresh_token(client, settings, session, fake_google):
    fake_google.payload.pop("refresh_token")
    state = make_state(settings, str(uuid.uuid4()))

    response = await client.get(f"/oauth/google/callback?code=c&state={state}")

    assert response.status_code == 200
    row = (await session.execute(select(ConnectedAccount))).scalar_one()
    assert row.encrypted_refresh_token is None


async def test_callback_tampered_state_400(client, settings, session, fake_google):
    state = make_state(settings, str(uuid.uuid4()))
    decoded = base64.urlsafe_b64decode(state.encode()).decode()
    parts = decoded.split("|")
    parts[0] = str(uuid.uuid4())
    forged = base64.urlsafe_b64encode("|".join(parts).encode()).decode()

    response = await client.get(f"/oauth/google/callback?code=c&state={forged}")

    assert response.status_code == 400
    # The code was never exchanged and nothing was stored.
    assert fake_google.calls == []
    assert (await session.execute(select(ConnectedAccount))).scalars().all() == []


async def test_callback_expired_state_400(client, settings, fake_google):
    expired_minter = settings.model_copy(update={"oauth_state_ttl_seconds": -1})
    state = make_state(expired_minter, str(uuid.uuid4()))

    response = await client.get(f"/oauth/google/callback?code=c&state={state}")

    assert response.status_code == 400
    assert fake_google.calls == []


async def test_callback_provider_error_is_safe_400(client, settings, session, fake_google):
    fake_google.status_code = 500
    fake_google.text = '{"error":"boom","echo":"auth-code-123 test-client-secret"}'
    state = make_state(settings, str(uuid.uuid4()))

    response = await client.get(
        f"/oauth/google/callback?code=auth-code-123&state={state}"
    )

    assert response.status_code == 400
    assert "500" in response.json()["detail"]
    # Nothing from the provider's body (which can echo our secrets) leaks out.
    assert "auth-code-123" not in response.text
    assert "test-client-secret" not in response.text
    assert (await session.execute(select(ConnectedAccount))).scalars().all() == []


async def test_callback_unknown_provider_404(client, settings):
    state = make_state(settings, str(uuid.uuid4()))
    response = await client.get(f"/oauth/slack/callback?code=c&state={state}")
    assert response.status_code == 404


async def test_callback_missing_params_422(client):
    response = await client.get("/oauth/google/callback")
    assert response.status_code == 422


async def test_callback_user_denied_consent_400(client, fake_google, session):
    """A provider error redirect (?error=access_denied) is a clean 400."""
    response = await client.get("/oauth/google/callback?error=access_denied")

    assert response.status_code == 400
    assert "access_denied" in response.json()["detail"]
    assert fake_google.calls == []
    assert (await session.execute(select(ConnectedAccount))).scalars().all() == []


async def test_callback_unvetted_provider_error_not_echoed(client, fake_google):
    """Arbitrary error text from the redirect is never echoed back."""
    response = await client.get(
        "/oauth/google/callback?error=%3Cscript%3Ealert(1)%3C/script%3E"
    )

    assert response.status_code == 400
    assert "script" not in response.text
    assert "unknown_error" in response.json()["detail"]


async def test_callback_non_ascii_state_signature_400(client, settings, fake_google):
    """A crafted state with a non-ASCII signature must be a 400, not a 500."""
    payload = f"{uuid.uuid4()}|9999999999|deadbeef|sígnature-ñon-ascii"
    forged = base64.urlsafe_b64encode(payload.encode()).decode()

    response = await client.get(f"/oauth/google/callback?code=c&state={forged}")

    assert response.status_code == 400
    assert fake_google.calls == []
