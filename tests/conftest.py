"""Shared test fixtures.

Tests run against SQLite (in-memory) and the local key manager — no external
services required. All fixtures inject dependencies explicitly; nothing reads
the real environment.
"""

import base64
import os

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from credbroker.config import Settings
from credbroker.db.models import Base


@pytest.fixture
def settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite://",
        kms_key_id="",  # local key manager
        local_master_key_b64=base64.b64encode(os.urandom(32)).decode(),
        google_client_id="test-client-id",
        google_client_secret="test-client-secret",
        oauth_state_secret="test-state-secret",
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
