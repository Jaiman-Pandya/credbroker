"""Tests for process wiring in credbroker.main.

``build_servers`` is exercised with the app and gRPC builders monkeypatched
to capture their arguments, so no sockets are bound and no backends are
touched. What matters here is the plumbing itself: the one shared HTTP
client must reach both servers, uvicorn's logging must stay under the root
redaction filter, and SIGTERM/SIGINT must stop both servers cleanly.
"""

import asyncio
import logging
import os
import signal
from types import SimpleNamespace

import pytest

from credbroker import main as main_module
from credbroker.main import _SHUTDOWN_GRACE_SECONDS, build_servers, install_signal_handlers


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
    # The rest of the dependency set must arrive untranslated too.
    assert captured_builders["build_grpc_server"]["redis_client"] is redis_client
    for name in ("create_app", "build_grpc_server"):
        assert captured_builders[name]["settings"] is settings
        assert captured_builders[name]["session_factory"] is session_factory
        assert captured_builders[name]["cipher"] is cipher


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
