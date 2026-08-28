"""Tests for the Redis grant cache and fixed-window rate limiter.

All tests run against fakeredis (see the ``redis_client`` conftest fixture);
no real Redis is required. Time travel is deliberately avoided — TTL behavior
is asserted via the TTLs Redis reports, not by waiting for expiry.
"""

import hashlib

from credbroker.cache import GrantCache, RateLimiter


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class TestGrantCache:
    async def test_record_issued_sets_key_with_ttl(self, redis_client):
        cache = GrantCache(redis_client)
        token_hash = _hash("token-a")

        await cache.record_issued(token_hash, ttl_seconds=300)

        assert await cache.is_known(token_hash) is True
        ttl = await redis_client.ttl(f"grant:{token_hash}")
        assert 0 < ttl <= 300

    async def test_unknown_hash_is_neither_known_nor_revoked(self, redis_client):
        cache = GrantCache(redis_client)
        token_hash = _hash("never-issued")

        assert await cache.is_known(token_hash) is False
        assert await cache.is_revoked(token_hash) is False

    async def test_issue_then_revoke_lifecycle(self, redis_client):
        cache = GrantCache(redis_client)
        token_hash = _hash("token-b")

        await cache.record_issued(token_hash, ttl_seconds=300)
        assert await cache.is_known(token_hash) is True
        assert await cache.is_revoked(token_hash) is False

        await cache.record_revoked(token_hash)
        assert await cache.is_revoked(token_hash) is True
        # Revocation drops the issued entry so the two never disagree.
        assert await cache.is_known(token_hash) is False
        assert await redis_client.exists(f"grant:{token_hash}") == 0

    async def test_revoked_marker_has_default_ttl(self, redis_client):
        cache = GrantCache(redis_client)
        token_hash = _hash("token-c")

        await cache.record_revoked(token_hash)

        ttl = await redis_client.ttl(f"revoked:{token_hash}")
        assert 0 < ttl <= 600

    async def test_revoked_marker_honors_custom_ttl(self, redis_client):
        cache = GrantCache(redis_client)
        token_hash = _hash("token-d")

        await cache.record_revoked(token_hash, ttl_seconds=42)

        ttl = await redis_client.ttl(f"revoked:{token_hash}")
        assert 0 < ttl <= 42

    async def test_revoke_of_never_cached_grant_still_marks_revoked(self, redis_client):
        # A grant issued before a Redis flush can still be revoked; the marker
        # must not depend on the issued entry existing.
        cache = GrantCache(redis_client)
        token_hash = _hash("token-e")

        await cache.record_revoked(token_hash)

        assert await cache.is_revoked(token_hash) is True

    async def test_distinct_hashes_are_independent(self, redis_client):
        cache = GrantCache(redis_client)
        hash_a, hash_b = _hash("token-f"), _hash("token-g")

        await cache.record_issued(hash_a, ttl_seconds=300)
        await cache.record_issued(hash_b, ttl_seconds=300)
        await cache.record_revoked(hash_a)

        assert await cache.is_revoked(hash_a) is True
        assert await cache.is_revoked(hash_b) is False
        assert await cache.is_known(hash_b) is True

    async def test_cache_miss_is_not_authoritative_after_flush(self, redis_client):
        # A Redis flush wipes both entry kinds. The resulting misses must read
        # as "no cached record" — callers fall through to the DB, which stays
        # the source of truth for both validity and revocation.
        cache = GrantCache(redis_client)
        token_hash = _hash("token-h")
        await cache.record_issued(token_hash, ttl_seconds=300)
        await cache.record_revoked(token_hash)

        await redis_client.flushall()

        assert await cache.is_known(token_hash) is False
        assert await cache.is_revoked(token_hash) is False


class TestRateLimiter:
    async def test_allows_up_to_limit_then_blocks(self, redis_client):
        limiter = RateLimiter(redis_client)

        for _ in range(5):
            assert await limiter.check("grants:agent-1", limit=5) is True
        assert await limiter.check("grants:agent-1", limit=5) is False
        # Still blocked on subsequent attempts within the same window.
        assert await limiter.check("grants:agent-1", limit=5) is False

    async def test_separate_keys_have_independent_budgets(self, redis_client):
        limiter = RateLimiter(redis_client)

        for _ in range(3):
            assert await limiter.check("invoke:agent-1", limit=3) is True
        assert await limiter.check("invoke:agent-1", limit=3) is False

        # A different agent (and a different operation namespace) is unaffected.
        assert await limiter.check("invoke:agent-2", limit=3) is True
        assert await limiter.check("grants:agent-1", limit=3) is True

    async def test_window_counter_expires_with_window(self, redis_client):
        limiter = RateLimiter(redis_client)

        await limiter.check("grants:agent-3", limit=10, window_seconds=60)

        keys = await redis_client.keys("ratelimit:grants:agent-3:*")
        assert len(keys) == 1
        ttl = await redis_client.ttl(keys[0])
        assert 0 < ttl <= 60

    async def test_denied_requests_still_count(self, redis_client):
        limiter = RateLimiter(redis_client)

        await limiter.check("grants:agent-4", limit=1)
        await limiter.check("grants:agent-4", limit=1)

        keys = await redis_client.keys("ratelimit:grants:agent-4:*")
        assert int(await redis_client.get(keys[0])) == 2

    async def test_limit_zero_blocks_everything(self, redis_client):
        limiter = RateLimiter(redis_client)

        assert await limiter.check("grants:agent-5", limit=0) is False
