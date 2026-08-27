"""Outbound reliability primitives.

Everything the broker needs to talk to flaky providers safely: a circuit
breaker and retry helper (:mod:`credbroker.reliability.retry`) and a
Redis-backed idempotency store (:mod:`credbroker.reliability.idempotency`).
These modules never see raw provider credentials — they operate on opaque
callables and JSON-serializable results only.
"""

from credbroker.reliability.idempotency import IdempotencyStore
from credbroker.reliability.retry import CircuitBreaker, call_with_retries, default_retryable

__all__ = [
    "CircuitBreaker",
    "IdempotencyStore",
    "call_with_retries",
    "default_retryable",
]
