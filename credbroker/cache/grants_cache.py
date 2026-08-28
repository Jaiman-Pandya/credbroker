"""Redis cache of issued and revoked grant token hashes.

The cache exists to make two hot-path checks cheap for the invoke service:

* ``is_revoked`` — a fast pre-check (and mid-flight re-check) that lets a
  revocation propagate to every broker instance within one Redis round trip,
  ahead of the authoritative DB read.
* ``is_known`` — an advisory hint that a token hash was recently issued.

Only SHA-256 hashes of grant tokens are stored, never the tokens themselves,
so the cache holds no usable credential material.

AUTHORITY MODEL — a cache MISS is never authoritative. Redis may be flushed,
evict keys under memory pressure, or simply be a fresh instance; none of that
may invalidate (or resurrect) a real grant. Callers must treat:

* ``is_revoked(...) is False`` as "not known to be revoked *here*" and still
  consult the ``grants.revoked_at`` column before trusting a token, and
* ``is_known(...) is False`` as "no cached record", not "grant does not exist".

Only a cache HIT on the revocation key is safe to act on directly (deny), and
only because it fails closed. The database remains the source of truth.
"""

_ISSUED_PREFIX = "grant:"
_REVOKED_PREFIX = "revoked:"

#: How long a revocation marker outlives the revocation by default. Grant
#: tokens live for minutes (``grant_token_ttl_seconds``), so ten minutes
#: comfortably covers the remaining lifetime of any token being revoked.
DEFAULT_REVOKED_TTL_SECONDS = 600


class GrantCache:
    """Advisory Redis cache of grant-token state, keyed by token hash.

    The injected ``redis`` client is an async client (``redis.asyncio`` or
    fakeredis's aioredis) created with ``decode_responses=True``.
    """

    def __init__(self, redis):
        self._redis = redis

    async def record_issued(self, token_hash: str, ttl_seconds: int) -> None:
        """Cache a freshly issued grant's token hash for ``ttl_seconds``.

        The TTL mirrors the grant token's own lifetime, so the cache entry
        and the token expire together. Loss of this key (eviction, flush)
        merely loses the hint — the grant row in the DB stays valid.
        """
        await self._redis.set(f"{_ISSUED_PREFIX}{token_hash}", "1", ex=ttl_seconds)

    async def record_revoked(
        self, token_hash: str, ttl_seconds: int = DEFAULT_REVOKED_TTL_SECONDS
    ) -> None:
        """Mark a grant's token hash as revoked and drop its issued entry.

        The revocation marker needs to live only as long as the token could
        otherwise still be presented; after the token's ``exp`` passes, the
        JWT check denies it anyway. ``grants.revoked_at`` in the database is
        the permanent record — this key only accelerates propagation.
        """
        key = f"{_REVOKED_PREFIX}{token_hash}"
        await self._redis.set(key, "1", ex=ttl_seconds)
        await self._redis.delete(f"{_ISSUED_PREFIX}{token_hash}")

    async def is_revoked(self, token_hash: str) -> bool:
        """Return True if this token hash has a cached revocation marker.

        True is safe to act on (deny the call). False means only "no cached
        revocation" — the caller MUST still check ``revoked_at`` in the DB,
        because a Redis flush or expired marker does not un-revoke a grant.
        """
        return bool(await self._redis.exists(f"{_REVOKED_PREFIX}{token_hash}"))

    async def is_known(self, token_hash: str) -> bool:
        """Return True if this token hash has a cached issued entry.

        Purely advisory: False does NOT mean the grant is invalid or absent
        (the entry may have expired or been evicted), and callers must fall
        through to the database rather than rejecting on a miss.
        """
        return bool(await self._redis.exists(f"{_ISSUED_PREFIX}{token_hash}"))
