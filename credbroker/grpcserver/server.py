"""gRPC server assembly.

``build_grpc_server`` wires the Redis-backed grant cache, rate limiter, and
idempotency store together with the invoke service, registers the servicer,
and binds the listening port. All dependencies are injected by the caller
(see ``credbroker.main``); nothing here reads the environment or creates
clients of its own.
"""

import grpc

from credbroker.config import Settings
from credbroker.grpcserver.servicer import CredBrokerServicer
from credbroker.proto import credbroker_pb2_grpc


def build_grpc_server(
    *,
    settings: Settings,
    session_factory,
    cipher,
    redis_client,
    http_client=None,
) -> grpc.aio.Server:
    """Construct a ready-to-start ``grpc.aio.Server`` for the broker.

    The server listens on ``[::]:{settings.grpc_port}``; the caller is
    responsible for ``start()``/``stop()`` and for the lifetimes of the
    injected engine, Redis client, and HTTP client.
    """
    # Function-scope imports, deliberately: these components are separate
    # build units, and deferring keeps this module importable on its own
    # (and free of import cycles) while siblings are still being built.
    from credbroker.cache.grants_cache import GrantCache
    from credbroker.cache.ratelimit import RateLimiter
    from credbroker.invoke.service import InvokeService
    from credbroker.reliability.idempotency import IdempotencyStore

    grant_cache = GrantCache(redis_client)
    rate_limiter = RateLimiter(redis_client)
    idempotency_store = IdempotencyStore(redis_client, settings.idempotency_window_seconds)
    invoke_service = InvokeService(
        settings=settings,
        session_factory=session_factory,
        cipher=cipher,
        grant_cache=grant_cache,
        rate_limiter=rate_limiter,
        idempotency_store=idempotency_store,
        http_client=http_client,
    )

    server = grpc.aio.server()
    servicer = CredBrokerServicer(
        settings=settings,
        session_factory=session_factory,
        grant_cache=grant_cache,
        rate_limiter=rate_limiter,
        invoke_service=invoke_service,
    )
    credbroker_pb2_grpc.add_CredBrokerServicer_to_server(servicer, server)
    server.add_insecure_port(f"[::]:{settings.grpc_port}")
    return server
