"""Shared test fixtures.

Tests run against SQLite (in-memory), fakeredis, and the local key manager —
no external services required. All fixtures inject dependencies explicitly;
nothing reads the real environment.
"""

import base64
import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from credbroker.config import Settings
from credbroker.db.models import Base


@pytest.fixture(scope="session")
def rsa_keypair() -> tuple[str, str]:
    """(private_pem, public_pem) for signing grant tokens in tests."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = (
        key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return private_pem, public_pem


@pytest.fixture
def settings(rsa_keypair) -> Settings:
    private_pem, public_pem = rsa_keypair
    return Settings(
        database_url="sqlite+aiosqlite://",
        kms_key_id="",  # local key manager
        local_master_key_b64=base64.b64encode(os.urandom(32)).decode(),
        jwt_private_key_pem=private_pem,
        jwt_public_key_pem=public_pem,
        google_client_id="test-client-id",
        google_client_secret="test-client-secret",
        oauth_state_secret="test-state-secret",
        outbound_base_delay_seconds=0.001,
        _env_file=None,
    )


@pytest.fixture
async def engine():
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
def session_factory(engine):
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.fixture
async def session(session_factory):
    async with session_factory() as s:
        yield s


@pytest.fixture
async def redis_client():
    import fakeredis.aioredis

    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    yield client
    await client.aclose()
