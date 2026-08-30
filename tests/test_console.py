"""Tests for the operator console REST API (credbroker.console.api).

The app is assembled by hand here — the console router plus every app.state
attribute create_app would wire — so the console surface is exercised in
isolation against SQLite, fakeredis, and an httpx.MockTransport playing the
Drive provider. Alongside the endpoint behavior, these tests pin the
console's security posture: listing responses never carry encrypted blobs,
decrypted credentials, grant tokens, or JWT keys.
"""

import base64
import uuid

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select, update

from credbroker.cache.grants_cache import GrantCache
from credbroker.cache.ratelimit import RateLimiter
from credbroker.console.api import router as console_router
from credbroker.crypto.kms import build_token_cipher
from credbroker.db.models import ConnectedAccount, Grant, utcnow
from credbroker.demo.seed import DEMO_ACCESS_TOKEN
from credbroker.invoke.service import InvokeService
from credbroker.logging_config import clear_registry
from credbroker.reliability.idempotency import IdempotencyStore

CONSOLE_TOKEN = "console-secret-token"
DRIVE_RESULT = {
    "files": [
        {"id": "demo-1", "name": "roadmap.pdf", "mimeType": "application/pdf"},
        {"id": "demo-2", "name": "notes.txt", "mimeType": "text/plain"},
    ]
}


class FakeDrive:
    """MockTransport handler standing in for the Drive files endpoint."""

    def __init__(self):
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if not request.headers.get("authorization", "").startswith("Bearer "):
            return httpx.Response(401, json={"error": {"message": "missing bearer"}})
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
def fake_drive():
    return FakeDrive()


@pytest.fixture
async def provider_client(fake_drive):
    client = httpx.AsyncClient(transport=httpx.MockTransport(fake_drive.handler))
    yield client
    await client.aclose()


def build_console_app(
    *, settings, session_factory, cipher, redis_client, provider_client
) -> FastAPI:
    """Assemble the console app by hand: the router plus what create_app wires."""
    app = FastAPI()
    app.state.settings = settings
    app.state.session_factory = session_factory
    app.state.cipher = cipher
    app.state.http_client = provider_client
    app.state.redis_client = redis_client
    app.state.grant_cache = GrantCache(redis_client)
    app.state.rate_limiter = RateLimiter(redis_client)
    app.state.idempotency_store = IdempotencyStore(
        redis_client, settings.idempotency_window_seconds
    )
    app.state.invoke_service = InvokeService(
        settings=settings,
        session_factory=session_factory,
        cipher=cipher,
        grant_cache=app.state.grant_cache,
        rate_limiter=app.state.rate_limiter,
        idempotency_store=app.state.idempotency_store,
        http_client=provider_client,
    )
    app.include_router(console_router)
    return app


@pytest.fixture
def app(settings, session_factory, cipher, redis_client, provider_client):
    return build_console_app(
        settings=settings,
        session_factory=session_factory,
        cipher=cipher,
        redis_client=redis_client,
        provider_client=provider_client,
    )


@pytest.fixture
async def client(app):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


async def seed(client) -> dict:
    response = await client.post("/console/api/demo/seed")
    assert response.status_code == 200
    return response.json()


async def issue_grant(client, agent_id: str) -> dict:
    response = await client.post(
        "/console/api/grants",
        json={"agent_id": agent_id, "tool_name": "drive.read", "requested_scope": "read"},
    )
    assert response.status_code == 200
    return response.json()


async def test_tools_listing(client):
    response = await client.get("/console/api/tools")

    assert response.status_code == 200
    tools = response.json()
    drive = next(t for t in tools if t["name"] == "drive.read")
    assert drive == {
        "name": "drive.read",
        "provider": "google",
        "scope": "read",
        "side_effectful": False,
    }


async def test_seed_is_idempotent_and_rows_are_listed(client):
    first = await seed(client)
    second = await seed(client)

    assert first["created"] is True
    assert second["created"] is False
    # Same rows on the second call, all serialized as UUID strings.
    for key in ("user_id", "agent_id", "connected_account_id"):
        assert uuid.UUID(first[key])
        assert second[key] == first[key]

    agents = (await client.get("/console/api/agents")).json()
    assert [a["name"] for a in agents] == ["demo agent"]
    assert agents[0]["id"] == first["agent_id"]
    assert agents[0]["allowed_scopes"] == ["drive.read"]
    assert agents[0]["created_at"] is not None

    accounts = (await client.get("/console/api/accounts")).json()
    assert len(accounts) == 1
    account = accounts[0]
    assert account["id"] == first["connected_account_id"]
    assert account["user_id"] == first["user_id"]
    assert account["provider"] == "google"
    assert account["scopes_granted"] == ["demo"]
    # Identifying columns only — the encrypted columns must not even have keys.
    assert set(account) == {
        "id",
        "user_id",
        "provider",
        "scopes_granted",
        "expires_at",
        "created_at",
    }


async def test_create_agent_generates_user_id_when_omitted(client):
    response = await client.post(
        "/console/api/agents",
        json={"name": "ops-agent", "allowed_scopes": ["drive.read"]},
    )

    assert response.status_code == 200
    agent = response.json()
    assert agent["name"] == "ops-agent"
    assert agent["allowed_scopes"] == ["drive.read"]
    assert uuid.UUID(agent["user_id"])  # generated

    explicit_user = str(uuid.uuid4())
    response = await client.post(
        "/console/api/agents",
        json={"name": "second-agent", "allowed_scopes": [], "user_id": explicit_user},
    )
    assert response.json()["user_id"] == explicit_user


async def test_grant_issue_and_listing(client, session):
    seeded = await seed(client)

    issued = await issue_grant(client, seeded["agent_id"])

    assert uuid.UUID(issued["grant_id"])
    assert issued["grant_token"].count(".") == 2  # a signed JWT, not a stub
    assert issued["expires_at"] is not None

    rows = (await client.get("/console/api/grants")).json()
    assert len(rows) == 1
    row = rows[0]
    assert row["id"] == issued["grant_id"]
    assert row["agent_id"] == seeded["agent_id"]
    assert row["connected_account_id"] == seeded["connected_account_id"]
    assert row["tool_name"] == "drive.read"
    assert row["scope"] == "read"
    assert row["status"] == "active"
    assert row["revoked_at"] is None
    # Neither the token nor its hash may appear in listings.
    assert set(row) == {
        "id",
        "agent_id",
        "connected_account_id",
        "tool_name",
        "scope",
        "issued_at",
        "expires_at",
        "revoked_at",
        "status",
    }


async def test_grant_listing_marks_expired_rows(client, session):
    seeded = await seed(client)
    issued = await issue_grant(client, seeded["agent_id"])
    await session.execute(
        update(Grant)
        .where(Grant.id == uuid.UUID(issued["grant_id"]))
        .values(expires_at=utcnow())
    )
    await session.commit()

    rows = (await client.get("/console/api/grants")).json()

    assert [r["status"] for r in rows] == ["expired"]


async def test_invoke_success_and_audit_trail(client, fake_drive):
    seeded = await seed(client)
    issued = await issue_grant(client, seeded["agent_id"])

    response = await client.post(
        "/console/api/invoke",
        json={
            "grant_token": issued["grant_token"],
            "tool_name": "drive.read",
            "arguments": {"page_size": 5},
        },
    )

    assert response.status_code == 200
    outcome = response.json()
    assert outcome["status"] == "success"
    assert outcome["result"] == DRIVE_RESULT
    assert outcome["error"] is None
    assert outcome["denied_reason"] is None
    assert outcome["from_cache"] is False
    assert isinstance(outcome["latency_ms"], int)
    # The seeded placeholder credential went out as the bearer token.
    assert len(fake_drive.requests) == 1
    assert fake_drive.requests[0].headers["authorization"] == f"Bearer {DEMO_ACCESS_TOKEN}"

    audit = (await client.get("/console/api/audit")).json()
    assert len(audit) == 1
    row = audit[0]
    assert row["grant_id"] == issued["grant_id"]
    assert row["tool_name"] == "drive.read"
    assert row["status"] == "success"
    assert isinstance(row["latency_ms"], int)
    assert row["arguments_hash"]
    assert row["called_at"] is not None


async def test_revoke_then_invoke_denied(client, fake_drive):
    seeded = await seed(client)
    issued = await issue_grant(client, seeded["agent_id"])

    revoked = await client.post(f"/console/api/grants/{issued['grant_id']}/revoke")
    assert revoked.status_code == 200
    assert revoked.json() == {"revoked": True}

    response = await client.post(
        "/console/api/invoke",
        json={"grant_token": issued["grant_token"], "tool_name": "drive.read", "arguments": {}},
    )
    outcome = response.json()
    assert outcome["status"] == "denied"
    assert outcome["denied_reason"] == "revoked"
    assert fake_drive.requests == []

    rows = (await client.get("/console/api/grants")).json()
    assert [r["status"] for r in rows] == ["revoked"]
    assert rows[0]["revoked_at"] is not None


async def test_revoke_unknown_grant_is_404(client):
    response = await client.post(f"/console/api/grants/{uuid.uuid4()}/revoke")

    assert response.status_code == 404


async def test_grant_for_unknown_agent_is_404(client):
    response = await client.post(
        "/console/api/grants",
        json={
            "agent_id": str(uuid.uuid4()),
            "tool_name": "drive.read",
            "requested_scope": "read",
        },
    )

    assert response.status_code == 404


async def test_policy_denied_maps_to_403(client):
    created = await client.post(
        "/console/api/agents", json={"name": "no-scopes-agent", "allowed_scopes": []}
    )

    response = await client.post(
        "/console/api/grants",
        json={
            "agent_id": created.json()["id"],
            "tool_name": "drive.read",
            "requested_scope": "read",
        },
    )

    assert response.status_code == 403


async def test_concurrency_limit_maps_to_429(client):
    seeded = await seed(client)
    await issue_grant(client, seeded["agent_id"])

    response = await client.post(
        "/console/api/grants",
        json={
            "agent_id": seeded["agent_id"],
            "tool_name": "drive.read",
            "requested_scope": "read",
        },
    )

    # max_active_grants_per_agent_scope defaults to 1: the second issue trips it.
    assert response.status_code == 429


async def test_console_token_enforced_when_set(
    settings, session_factory, cipher, redis_client, provider_client
):
    guarded = build_console_app(
        settings=settings.model_copy(update={"console_token": CONSOLE_TOKEN}),
        session_factory=session_factory,
        cipher=cipher,
        redis_client=redis_client,
        provider_client=provider_client,
    )
    transport = httpx.ASGITransport(app=guarded)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        missing = await c.get("/console/api/tools")
        wrong = await c.get("/console/api/tools", headers={"X-Console-Token": "nope"})
        right = await c.get("/console/api/tools", headers={"X-Console-Token": CONSOLE_TOKEN})

    assert missing.status_code == 401
    assert wrong.status_code == 401
    assert right.status_code == 200


async def test_console_open_when_token_empty(client):
    # The default settings fixture leaves console_token empty: no header needed.
    response = await client.get("/console/api/tools")

    assert response.status_code == 200


async def test_console_page_is_served(client):
    response = await client.get("/console")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


async def test_listings_never_leak_secret_material(client, session, settings):
    seeded = await seed(client)
    issued = await issue_grant(client, seeded["agent_id"])
    invoked = await client.post(
        "/console/api/invoke",
        json={"grant_token": issued["grant_token"], "tool_name": "drive.read", "arguments": {}},
    )
    assert invoked.json()["status"] == "success"

    account = (await session.execute(select(ConnectedAccount))).scalars().one()
    grant = (await session.execute(select(Grant))).scalars().one()
    blob = account.encrypted_access_token
    secrets = [
        DEMO_ACCESS_TOKEN,  # the decrypted credential
        base64.b64encode(blob).decode(),  # the encrypted blob, as JSON would carry it
        blob.hex(),  # ... or hex-encoded
        issued["grant_token"],  # the signed grant token
        grant.grant_token_hash,  # omitted from listings by contract
        settings.jwt_private_key_pem.strip(),
        settings.jwt_public_key_pem.strip(),
    ]

    for path in (
        "/console/api/accounts",
        "/console/api/agents",
        "/console/api/grants",
        "/console/api/audit",
    ):
        response = await client.get(path)
        assert response.status_code == 200
        body = response.text
        for secret in secrets:
            assert secret not in body, f"secret material leaked in {path}"
