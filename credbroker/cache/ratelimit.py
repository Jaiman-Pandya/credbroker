"""Fixed-window rate limiting backed by Redis.

Each (key, window) pair maps to a Redis counter named
``ratelimit:{key}:{window_index}``, where the window index is the current
Unix time divided by the window length. Counters expire on their own, so no
cleanup pass is needed. Fixed windows admit up to 2x the limit across a
window boundary in the worst case; that is an accepted trade-off for a
single INCR per check on the hot path.

The limiter is a protective throttle, not a security boundary: if Redis is
flushed the current window's counts restart at zero, which briefly relaxes —
never wrongly tightens — the limit. Authorization decisions never depend on
limiter state.
"""

import time

_PREFIX = "ratelimit:"


class RateLimiter:
    """Fixed-window counter rate limiter.

    The injected ``redis`` client is an async client (``redis.asyncio`` or
    fakeredis's aioredis) created with ``decode_responses=True``.
    """

    def __init__(self, redis):
        self._redis = redis

    async def check(self, key: str, limit: int, window_seconds: int = 60) -> bool:
        """Count one request against ``key`` and report whether it is allowed.

        Returns True while the current fixed window has seen at most
        ``limit`` requests (this one included), False once the budget is
        exhausted. A denied request still increments the counter, so hammering
        a limited key does not help the caller.

        Callers pass a namespaced key such as ``"grants:{agent_id}"`` or
        ``"invoke:{agent_id}"``; the limiter adds its own ``ratelimit:``
        prefix and the window index.
        """
        window_index = int(time.time() // window_seconds)
        counter_key = f"{_PREFIX}{key}:{window_index}"
        count = await self._redis.incr(counter_key)
        if count == 1:
            # First hit in this window: bound the counter's lifetime. If this
            # EXPIRE were ever lost, the key still goes cold naturally because
            # the window index rolls the key name over every window.
            await self._redis.expire(counter_key, window_seconds)
        return count <= limit
