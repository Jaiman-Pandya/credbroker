"""Tests for process wiring in credbroker.main and credbroker.app.

``build_servers`` is exercised with the app and gRPC builders monkeypatched
to capture their arguments, so no sockets are bound and no backends are
touched. What matters here is the plumbing itself: the one shared HTTP
client and Redis client must reach both servers, uvicorn's logging must
stay under the root redaction filter, SIGTERM/SIGINT must stop both servers
cleanly, ``create_app`` must assemble the console's invoke stack on
``app.state``, and the dev-only JWT keypair fallback must engage exactly
when no key is configured.
"""

import asyncio
import logging
import os
import signal
from types import SimpleNamespace

import httpx
import pytest
from cryptography.hazmat.primitives import serialization

from credbroker import main as main_module
from credbroker.app import create_app
from credbroker.config import Settings
from credbroker.crypto.kms import build_token_cipher
from credbroker.main import (
    _SHUTDOWN_GRACE_SECONDS,
    build_servers,
    ensure_dev_jwt_keys,
    install_signal_handlers,
)


@pytest.fixture
def captured_builders(monkeypatch):
    """Monkeypatch create_app / build_grpc_server; record the kwargs each got."""
    calls: dict[str, dict] = {}

    def fake_create_app(**kwargs):
        calls["create_app"] = kwargs
        return SimpleNamespace(name="fake-asgi-app")

    def fake_build_grpc_server(**kwargs):
        calls["build_grpc_server"] = kwargs
        return SimpleNamespace(name="fake-grpc-server")

    monkeypatch.setattr(main_module, "create_app", fake_create_app)
    monkeypatch.setattr(main_module, "build_grpc_server", fake_build_grpc_server)
    return calls


def test_shared_http_client_reaches_both_servers(settings, captured_builders):
    """Regression: build_grpc_server was once called without http_client,
    leaving the production InvokeService with None."""
    http_client = object()
    session_factory = object()
    cipher = object()
    redis_client = object()

    build_servers(
        settings=settings,
        session_factory=session_factory,
        cipher=cipher,
        redis_client=redis_client,
        http_client=http_client,
    )

    assert captured_builders["create_app"]["http_client"] is http_client
    assert captured_builders["build_grpc_server"]["http_client"] is http_client
    # The rest of the dependency set must arrive untranslated too. The Redis
    # client now reaches both servers as well: the console's invoke path and
    # the gRPC one must share revocation cache, limits, and idempotency keys.
    for name in ("create_app", "build_grpc_server"):
        assert captured_builders[name]["settings"] is settings
        assert captured_builders[name]["session_factory"] is session_factory
        assert captured_builders[name]["cipher"] is cipher
        assert captured_builders[name]["redis_client"] is redis_client


def test_uvicorn_config_keeps_logging_under_redaction_filter(settings, captured_builders):
    """uvicorn's default log config attaches its own handlers with
    propagate=False, which would route the OAuth callback's ?code=... past
    the root redaction filter and into the access log in cleartext."""
    http_server, _ = build_servers(
        settings=settings,
        session_factory=object(),
        cipher=object(),
        redis_client=object(),
        http_client=object(),
    )

    assert http_server.config.log_config is None
    assert http_server.config.access_log is False
    # With log_config=None, uvicorn's error logger propagates to root where
    # the redaction filter lives; access_log=False silences request lines
    # (and their query strings) entirely.
    assert logging.getLogger("uvicorn.error").propagate is True
    assert logging.getLogger("uvicorn.access").propagate is False
    assert logging.getLogger("uvicorn.access").handlers == []


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
async def test_signal_triggers_clean_stop_of_both_servers(sig):
    """Regression: nothing handled SIGTERM/SIGINT, so ECS stop killed the
    process mid-request and serve()'s finally-block cleanup never ran."""
    loop = asyncio.get_running_loop()
    http_server = SimpleNamespace(should_exit=False)
    stopped = asyncio.Event()

    class FakeGrpcServer:
        def __init__(self):
            self.grace: int | None = None

        async def stop(self, grace):
            self.grace = grace
            stopped.set()

    grpc_server = FakeGrpcServer()
    install_signal_handlers(http_server, grpc_server)
    try:
        os.kill(os.getpid(), sig)
        await asyncio.wait_for(stopped.wait(), timeout=5)
        assert http_server.should_exit is True
        assert grpc_server.grace == _SHUTDOWN_GRACE_SECONDS
    finally:
        for handled in (signal.SIGTERM, signal.SIGINT):
            loop.remove_signal_handler(handled)


async def test_create_app_builds_console_invoke_stack(settings, session_factory, redis_client):
    """With a Redis client, create_app must assemble the same collaborator
    set the gRPC side gets and expose it all on app.state; without one, the
    Redis-backed collaborators are None but the invoke service still exists
    (its database-backed security checks stand alone)."""
    from credbroker.cache.grants_cache import GrantCache
    from credbroker.cache.ratelimit import RateLimiter
    from credbroker.invoke.service import InvokeService
    from credbroker.reliability.idempotency import IdempotencyStore

    cipher = build_token_cipher(settings)
    async with httpx.AsyncClient() as http_client:
        app = create_app(
            settings=settings,
            session_factory=session_factory,
            cipher=cipher,
            http_client=http_client,
            redis_client=redis_client,
        )
        assert app.state.settings is settings
        assert app.state.session_factory is session_factory
        assert app.state.cipher is cipher
        assert app.state.http_client is http_client
        assert app.state.redis_client is redis_client
        assert isinstance(app.state.grant_cache, GrantCache)
        assert isinstance(app.state.rate_limiter, RateLimiter)
        assert isinstance(app.state.idempotency_store, IdempotencyStore)
        assert isinstance(app.state.invoke_service, InvokeService)
        # The console UI and API must be mounted. Inspect the OpenAPI schema
        # rather than app.routes: this FastAPI version defers included
        # routers, so their paths are not visible on the route list.
        paths = set(app.openapi()["paths"])
        assert "/console" in paths
        assert "/console/api/invoke" in paths

        bare = create_app(
            settings=settings,
            session_factory=session_factory,
            cipher=cipher,
            http_client=http_client,
        )
        assert bare.state.redis_client is None
        assert bare.state.grant_cache is None
        assert bare.state.rate_limiter is None
        assert bare.state.idempotency_store is None
        assert isinstance(bare.state.invoke_service, InvokeService)


def test_dev_jwt_keys_generated_when_unset(caplog):
    """serve()'s helper must mint an ephemeral signing keypair (with a loud
    warning) when none is configured, so a fresh checkout can issue grants."""
    bare = Settings(jwt_private_key_pem="", jwt_public_key_pem="", _env_file=None)
    with caplog.at_level(logging.WARNING, logger="credbroker.main"):
        updated = ensure_dev_jwt_keys(bare)

    assert updated is not bare  # model_copy, not mutation
    assert bare.jwt_private_key_pem == ""
    assert "will NOT survive a restart" in caplog.text
    assert updated.jwt_private_key_pem.startswith("-----BEGIN PRIVATE KEY-----")
    assert updated.jwt_public_key_pem.startswith("-----BEGIN PUBLIC KEY-----")
    # The two PEMs must actually be a pair.
    key = serialization.load_pem_private_key(
        updated.jwt_private_key_pem.encode(), password=None
    )
    derived_public = (
        key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    assert derived_public == updated.jwt_public_key_pem


def test_dev_jwt_keys_leave_configured_settings_untouched(settings, caplog):
    """A configured keypair passes through identically — no copy, no warning."""
    with caplog.at_level(logging.WARNING, logger="credbroker.main"):
        assert ensure_dev_jwt_keys(settings) is settings
    assert caplog.records == []
