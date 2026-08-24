"""FastAPI application factory.

The HTTP surface is intentionally tiny: OAuth connect flow (browsers need
HTTP redirects) and a health check. Everything agent-facing will speak gRPC.
"""

from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
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
) -> FastAPI:
    owns_client = http_client is None

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
    app.state.http_client = http_client or httpx.AsyncClient(timeout=15.0)

    app.include_router(oauth_router)

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok", "version": __version__}

    return app
