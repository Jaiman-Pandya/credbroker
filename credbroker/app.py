"""FastAPI application factory.

The HTTP surface: OAuth connect flow (browsers need HTTP redirects), the
operator console (UI plus its REST API), health check, and Prometheus
metrics. Everything agent-facing is gRPC — see credbroker.grpcserver.
"""

from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
from prometheus_client import make_asgi_app
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from credbroker import __version__
from credbroker.config import Settings
from credbroker.crypto.kms import TokenCipher
from credbroker.oauth.router import router as oauth_router


def create_app(
    *,
    settings: Settings,
    session_factory: async_sessionmaker[AsyncSession],
    cipher: TokenCipher,
    http_client: httpx.AsyncClient | None = None,
    redis_client=None,
) -> FastAPI:
    # Function-scope imports, deliberately: these components are separate
    # build units, and deferring keeps this module importable on its own
    # while siblings are still being built (same pattern as
    # credbroker.grpcserver.server).
    from credbroker.cache.grants_cache import GrantCache
    from credbroker.cache.ratelimit import RateLimiter
    from credbroker.console.api import router as console_router
    from credbroker.invoke.service import InvokeService
    from credbroker.reliability.idempotency import IdempotencyStore

    owns_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=15.0)

    # The Redis-backed collaborators are optional: without a Redis client the
    # console's invoke path skips the revocation fast path, rate limiting,
    # and idempotency, but every database-backed security check still runs.
    if redis_client is not None:
        grant_cache = GrantCache(redis_client)
        rate_limiter = RateLimiter(redis_client)
        idempotency_store = IdempotencyStore(redis_client, settings.idempotency_window_seconds)
    else:
        grant_cache = None
        rate_limiter = None
        idempotency_store = None

    # The invoke service receives the shared client, so it never owns one —
    # the lifespan below is the only place this client's lifetime is managed.
    invoke_service = InvokeService(
        settings=settings,
        session_factory=session_factory,
        cipher=cipher,
        grant_cache=grant_cache,
        rate_limiter=rate_limiter,
        idempotency_store=idempotency_store,
        http_client=client,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        # Only close a client we created; injected clients belong to the caller.
        if owns_client:
            await app.state.http_client.aclose()

    app = FastAPI(title="CredBroker", version=__version__, lifespan=lifespan)
    app.state.settings = settings
    app.state.session_factory = session_factory
    app.state.cipher = cipher
    app.state.http_client = client
    app.state.redis_client = redis_client
    app.state.grant_cache = grant_cache
    app.state.rate_limiter = rate_limiter
    app.state.idempotency_store = idempotency_store
    app.state.invoke_service = invoke_service

    app.include_router(oauth_router)
    app.include_router(console_router)

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok", "version": __version__}

    app.mount("/metrics", make_asgi_app())

    return app
