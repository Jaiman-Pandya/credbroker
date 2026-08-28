"""Agent-facing gRPC surface.

``servicer`` implements the CredBroker service (RequestGrant / InvokeTool /
RevokeGrant); ``server`` assembles a ``grpc.aio.Server`` with all runtime
dependencies wired in. This package deliberately re-exports nothing so that
each module can be imported independently while sibling components build.
"""
