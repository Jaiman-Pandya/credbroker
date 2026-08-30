"""Process entrypoint: runs the HTTP app and the gRPC server side by side."""

import asyncio
import logging
import signal

import grpc
import httpx
import redis.asyncio as aioredis
import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from credbroker.app import create_app
from credbroker.config import Settings, get_settings
from credbroker.crypto.kms import build_token_cipher
from credbroker.db.session import create_engine, create_session_factory
from credbroker.grpcserver.server import build_grpc_server
from credbroker.logging_config import configure_logging
from credbroker.tools import configure_tools

logger = logging.getLogger(__name__)

_SHUTDOWN_GRACE_SECONDS = 5


def ensure_dev_jwt_keys(settings: Settings) -> Settings:
    """Return settings guaranteed to carry a JWT grant-signing keypair.

    A configured keypair passes through untouched. When no private key is
    set, generate an ephemeral RSA keypair so a fresh checkout can issue
    grants with zero key setup — dev ergonomics only: the keys exist in this
    process alone, so every outstanding grant token dies with a restart.
    Production must always configure CREDBROKER_JWT_PRIVATE_KEY_PEM.
    """
    if settings.jwt_private_key_pem:
        return settings
    logger.warning(
        "CREDBROKER_JWT_PRIVATE_KEY_PEM is not set; generating an ephemeral "
        "RSA keypair for grant signing. Grants will NOT survive a restart — "
        "this is for development only, never run production this way."
    )
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
    # model_copy (not mutation) so the generated PEMs flow to every consumer
    # of this Settings instance without touching get_settings()'s cached one.
    return settings.model_copy(
        update={"jwt_private_key_pem": private_pem, "jwt_public_key_pem": public_pem}
    )


def build_servers(
    *,
    settings: Settings,
    session_factory,
    cipher,
    redis_client,
    http_client: httpx.AsyncClient,
) -> tuple[uvicorn.Server, grpc.aio.Server]:
    """Construct the HTTP and gRPC servers over one shared dependency set.

    Split out of ``serve()`` so the wiring is testable without binding
    sockets or touching real backends. The same ``http_client`` must reach
    both servers: the OAuth flow and outbound tool invocations share its
    connection pool, and ``serve()`` owns its lifetime. The same goes for
    ``redis_client``: the console's invoke path and the gRPC one must see
    the same revocation cache, rate limits, and idempotency keys.
    """
    app = create_app(
        settings=settings,
        session_factory=session_factory,
        cipher=cipher,
        http_client=http_client,
        redis_client=redis_client,
    )
    # log_config=None keeps uvicorn's loggers propagating to root, where the
    # secret-redaction filter lives (uvicorn's default config attaches its
    # own handlers with propagate=False, bypassing redaction entirely).
    # access_log=False because the OAuth callback URL carries the
    # authorization code in its query string, and access-log request lines
    # would record it in cleartext.
    http_config = uvicorn.Config(
        app,
        host=settings.http_host,
        port=settings.http_port,
        log_level="info",
        log_config=None,
        access_log=False,
    )
    http_server = uvicorn.Server(http_config)

    grpc_server = build_grpc_server(
        settings=settings,
        session_factory=session_factory,
        cipher=cipher,
        redis_client=redis_client,
        http_client=http_client,
    )
    return http_server, grpc_server


def install_signal_handlers(http_server: uvicorn.Server, grpc_server) -> None:
    """Route SIGTERM/SIGINT into a graceful stop of both servers.

    Without this, ECS task stop (SIGTERM) kills the process mid-request and
    ``serve()``'s finally block never runs. The handler flips uvicorn's
    ``should_exit`` and schedules ``grpc_server.stop(grace)``, so both halves
    of the ``gather`` in ``serve()`` return and cleanup stays reachable.
    """
    loop = asyncio.get_running_loop()

    def initiate_shutdown(sig: signal.Signals) -> None:
        logger.info("received %s, shutting down gracefully", sig.name)
        http_server.should_exit = True
        # grpc.aio stop() is a coroutine; run it on the loop. Repeated stop()
        # calls are safe, so the finally-block stop stays a harmless no-op.
        loop.create_task(grpc_server.stop(grace=_SHUTDOWN_GRACE_SECONDS))

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, initiate_shutdown, sig)


async def serve() -> None:
    configure_logging()
    settings = ensure_dev_jwt_keys(get_settings())
    configure_tools(settings)

    engine = create_engine(settings.database_url)
    session_factory = create_session_factory(engine)
    cipher = build_token_cipher(settings)
    redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)
    # One pooled client for all outbound HTTP: OAuth token exchange on the
    # app side and provider tool calls on the gRPC side.
    http_client = httpx.AsyncClient(timeout=15.0)

    http_server, grpc_server = build_servers(
        settings=settings,
        session_factory=session_factory,
        cipher=cipher,
        redis_client=redis_client,
        http_client=http_client,
    )

    await grpc_server.start()
    logger.info("gRPC server listening on port %d", settings.grpc_port)

    install_signal_handlers(http_server, grpc_server)

    try:
        await asyncio.gather(http_server.serve(), grpc_server.wait_for_termination())
    finally:
        await grpc_server.stop(grace=_SHUTDOWN_GRACE_SECONDS)
        await http_client.aclose()
        await redis_client.aclose()
        await engine.dispose()


def main() -> None:
    asyncio.run(serve())


if __name__ == "__main__":
    main()
