"""Tests for outbound reliability: circuit breaker, retries, idempotency.

Fully deterministic: the circuit breaker gets an injected fake monotonic
clock and ``call_with_retries`` gets a recording fake sleep, so no test ever
actually waits. Redis behavior is exercised against fakeredis via the shared
``redis_client`` fixture.
"""

import httpx
import pytest

from credbroker.errors import (
    IdempotencyConflictError,
    ProviderCallError,
    ProviderUnavailableError,
)
from credbroker.reliability.idempotency import (
    PENDING_MARKER,
    RESERVATION_TTL_SECONDS,
    IdempotencyStore,
)
from credbroker.reliability.retry import CircuitBreaker, call_with_retries, default_retryable


class FakeClock:
    """Injectable monotonic clock advanced explicitly by tests."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class SleepRecorder:
    """Async sleep stand-in that records requested delays and returns at once."""

    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


# ---------------------------------------------------------------------------
# CircuitBreaker
# ---------------------------------------------------------------------------


class TestCircuitBreaker:
    def test_starts_closed_and_allows(self, clock):
        cb = CircuitBreaker(failure_threshold=3, reset_seconds=30.0, clock=clock)
        assert cb.state == "closed"
        assert cb.allow() is True

    def test_opens_after_threshold_consecutive_failures(self, clock):
        cb = CircuitBreaker(failure_threshold=3, reset_seconds=30.0, clock=clock)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == "closed"
        assert cb.allow() is True
        cb.record_failure()
        assert cb.state == "open"
        assert cb.allow() is False

    def test_success_resets_consecutive_failure_count(self, clock):
        cb = CircuitBreaker(failure_threshold=2, reset_seconds=30.0, clock=clock)
        cb.record_failure()
        cb.record_success()
        cb.record_failure()
        assert cb.state == "closed"
        assert cb.allow() is True

    def test_half_opens_after_reset_window(self, clock):
        cb = CircuitBreaker(failure_threshold=1, reset_seconds=30.0, clock=clock)
        cb.record_failure()
        assert cb.state == "open"
        clock.advance(29.9)
        assert cb.allow() is False
        clock.advance(0.1)
        assert cb.state == "half_open"
        assert cb.allow() is True

    def test_half_open_success_closes(self, clock):
        cb = CircuitBreaker(failure_threshold=1, reset_seconds=30.0, clock=clock)
        cb.record_failure()
        clock.advance(30.0)
        assert cb.state == "half_open"
        cb.record_success()
        assert cb.state == "closed"
        assert cb.allow() is True

    def test_half_open_failure_reopens_for_full_window(self, clock):
        cb = CircuitBreaker(failure_threshold=1, reset_seconds=30.0, clock=clock)
        cb.record_failure()
        clock.advance(30.0)
        assert cb.state == "half_open"
        cb.record_failure()
        assert cb.state == "open"
        clock.advance(29.0)
        assert cb.allow() is False
        clock.advance(1.0)
        assert cb.state == "half_open"

    def test_half_open_admits_exactly_one_probe(self, clock):
        cb = CircuitBreaker(failure_threshold=1, reset_seconds=30.0, clock=clock)
        cb.record_failure()
        clock.advance(30.0)
        assert cb.allow() is True  # first caller claims the probe slot
        assert cb.allow() is False  # concurrent callers rejected as if open
        assert cb.allow() is False
        assert cb.state == "half_open"

    def test_half_open_probe_slot_frees_on_success(self, clock):
        cb = CircuitBreaker(failure_threshold=1, reset_seconds=30.0, clock=clock)
        cb.record_failure()
        clock.advance(30.0)
        assert cb.allow() is True
        cb.record_success()
        assert cb.state == "closed"
        assert cb.allow() is True

    def test_half_open_probe_failure_rearms_single_probe_next_window(self, clock):
        cb = CircuitBreaker(failure_threshold=1, reset_seconds=30.0, clock=clock)
        cb.record_failure()
        clock.advance(30.0)
        assert cb.allow() is True
        cb.record_failure()
        assert cb.state == "open"
        assert cb.allow() is False
        clock.advance(30.0)
        assert cb.allow() is True  # fresh window admits one new probe
        assert cb.allow() is False

    def test_rejects_nonsense_configuration(self, clock):
        with pytest.raises(ValueError):
            CircuitBreaker(failure_threshold=0, reset_seconds=30.0, clock=clock)
        with pytest.raises(ValueError):
            CircuitBreaker(failure_threshold=1, reset_seconds=-1.0, clock=clock)


# ---------------------------------------------------------------------------
# default_retryable
# ---------------------------------------------------------------------------


class TestDefaultRetryable:
    def test_httpx_timeouts_and_transport_errors_are_retryable(self):
        assert default_retryable(httpx.ConnectTimeout("timed out")) is True
        assert default_retryable(httpx.ReadTimeout("timed out")) is True
        assert default_retryable(httpx.ConnectError("refused")) is True

    def test_provider_5xx_is_retryable(self):
        assert default_retryable(ProviderCallError("boom", status_code=500)) is True
        assert default_retryable(ProviderCallError("boom", status_code=503)) is True

    def test_provider_4xx_and_unknown_status_are_not(self):
        assert default_retryable(ProviderCallError("nope", status_code=404)) is False
        assert default_retryable(ProviderCallError("nope", status_code=429)) is False
        assert default_retryable(ProviderCallError("nope", status_code=None)) is False

    def test_other_exceptions_are_not_retryable(self):
        assert default_retryable(ValueError("bad")) is False
        assert default_retryable(KeyError("bad")) is False


# ---------------------------------------------------------------------------
# call_with_retries
# ---------------------------------------------------------------------------


class CountingFn:
    """Zero-arg async callable that raises scripted exceptions, then succeeds."""

    def __init__(self, failures: list[Exception], result: dict | None = None):
        self.failures = list(failures)
        self.result = result if result is not None else {"ok": True}
        self.calls = 0

    async def __call__(self) -> dict:
        self.calls += 1
        if self.failures:
            raise self.failures.pop(0)
        return self.result


class TestCallWithRetries:
    async def test_returns_result_on_first_success(self):
        fn = CountingFn([], result={"files": []})
        sleeper = SleepRecorder()
        result = await call_with_retries(fn, max_retries=3, base_delay=1.0, sleep=sleeper)
        assert result == {"files": []}
        assert fn.calls == 1
        assert sleeper.delays == []

    async def test_5xx_retried_with_exponential_backoff_then_raises(self):
        errors = [ProviderCallError("boom", status_code=500) for _ in range(4)]
        fn = CountingFn(errors)
        sleeper = SleepRecorder()
        with pytest.raises(ProviderCallError) as excinfo:
            await call_with_retries(fn, max_retries=3, base_delay=0.5, sleep=sleeper)
        assert excinfo.value.status_code == 500
        assert fn.calls == 4  # initial attempt + 3 retries
        assert sleeper.delays == [0.5, 1.0, 2.0]

    async def test_transient_transport_failure_then_success(self, clock):
        fn = CountingFn([httpx.ConnectTimeout("t"), httpx.ConnectError("t")])
        sleeper = SleepRecorder()
        circuit = CircuitBreaker(failure_threshold=5, reset_seconds=30.0, clock=clock)
        result = await call_with_retries(
            fn, max_retries=3, base_delay=1.0, circuit=circuit, sleep=sleeper
        )
        assert result == {"ok": True}
        assert fn.calls == 3
        assert sleeper.delays == [1.0, 2.0]
        assert circuit.state == "closed"

    async def test_4xx_not_retried_and_does_not_trip_circuit(self, clock):
        fn = CountingFn([ProviderCallError("bad request", status_code=400)])
        sleeper = SleepRecorder()
        circuit = CircuitBreaker(failure_threshold=1, reset_seconds=30.0, clock=clock)
        with pytest.raises(ProviderCallError):
            await call_with_retries(
                fn, max_retries=3, base_delay=1.0, circuit=circuit, sleep=sleeper
            )
        assert fn.calls == 1
        assert sleeper.delays == []
        # A single failure would have tripped this circuit if it were recorded.
        assert circuit.state == "closed"

    async def test_open_circuit_short_circuits_without_calling(self, clock):
        circuit = CircuitBreaker(failure_threshold=1, reset_seconds=30.0, clock=clock)
        circuit.record_failure()
        fn = CountingFn([])
        sleeper = SleepRecorder()
        with pytest.raises(ProviderUnavailableError):
            await call_with_retries(
                fn, max_retries=3, base_delay=1.0, circuit=circuit, sleep=sleeper
            )
        assert fn.calls == 0
        assert sleeper.delays == []

    async def test_circuit_tripping_mid_retries_stops_further_attempts(self, clock):
        errors = [ProviderCallError("boom", status_code=502) for _ in range(6)]
        fn = CountingFn(errors)
        sleeper = SleepRecorder()
        circuit = CircuitBreaker(failure_threshold=2, reset_seconds=30.0, clock=clock)
        with pytest.raises(ProviderUnavailableError):
            await call_with_retries(
                fn, max_retries=5, base_delay=1.0, circuit=circuit, sleep=sleeper
            )
        assert fn.calls == 2  # circuit opened after the second failure
        assert circuit.state == "open"

    async def test_half_open_probe_success_closes_circuit(self, clock):
        circuit = CircuitBreaker(failure_threshold=1, reset_seconds=30.0, clock=clock)
        circuit.record_failure()
        clock.advance(30.0)
        fn = CountingFn([])
        result = await call_with_retries(
            fn, max_retries=0, base_delay=1.0, circuit=circuit, sleep=SleepRecorder()
        )
        assert result == {"ok": True}
        assert circuit.state == "closed"

    async def test_rejects_nonsense_arguments(self):
        fn = CountingFn([])
        with pytest.raises(ValueError):
            await call_with_retries(fn, max_retries=-1, base_delay=1.0)
        with pytest.raises(ValueError):
            await call_with_retries(fn, max_retries=1, base_delay=-0.1)
        assert fn.calls == 0


# ---------------------------------------------------------------------------
# IdempotencyStore
# ---------------------------------------------------------------------------


class TestIdempotencyStore:
    @pytest.fixture
    def store(self, redis_client) -> IdempotencyStore:
        return IdempotencyStore(redis_client, window_seconds=3600)

    async def test_get_unseen_key_returns_none(self, store):
        assert await store.get("agent:tool:key1") is None

    async def test_reserve_claims_key_once(self, store):
        owner = await store.reserve("k")
        assert owner  # truthy token, compatible with `if not await reserve(...)`
        assert isinstance(owner, str)
        assert await store.reserve("k") is None

    async def test_reserve_owner_tokens_are_unique(self, store):
        first = await store.reserve("a")
        second = await store.reserve("b")
        assert first != second

    async def test_get_raises_conflict_while_pending(self, store):
        await store.reserve("k")
        with pytest.raises(IdempotencyConflictError):
            await store.get("k")

    async def test_reserve_uses_namespaced_key_and_pending_ttl(self, store, redis_client):
        owner = await store.reserve("k")
        assert await redis_client.get("idem:k") == f"{PENDING_MARKER}:{owner}"
        ttl = await redis_client.ttl("idem:k")
        assert 0 < ttl <= RESERVATION_TTL_SECONDS

    async def test_complete_replaces_marker_with_result_for_window(self, store, redis_client):
        await store.reserve("k")
        await store.complete("k", {"files": [{"id": "1"}], "count": 1})
        assert await store.get("k") == {"files": [{"id": "1"}], "count": 1}
        ttl = await redis_client.ttl("idem:k")
        assert 0 < ttl <= 3600
        # And a completed key can no longer be reserved within the window.
        assert await store.reserve("k") is None

    async def test_release_drops_marker_so_retry_can_proceed(self, store):
        owner = await store.reserve("k")
        await store.release("k", owner)
        assert await store.get("k") is None
        assert await store.reserve("k") is not None

    async def test_release_never_discards_a_completed_result(self, store):
        await store.reserve("k")
        await store.complete("k", {"ok": True})
        await store.release("k")  # late/duplicate release must be a no-op here
        assert await store.get("k") == {"ok": True}

    async def test_release_of_unknown_key_is_a_noop(self, store):
        await store.release("never-reserved")
        assert await store.get("never-reserved") is None

    async def test_stale_release_cannot_drop_a_successors_reservation(self, store, redis_client):
        stale = await store.reserve("k")
        # Simulate the reservation TTL expiring mid-call, then a retry
        # re-reserving the key.
        await redis_client.delete("idem:k")
        successor = await store.reserve("k")
        assert successor is not None
        await store.release("k", stale)  # stale holder must not free the key
        with pytest.raises(IdempotencyConflictError):
            await store.get("k")
        await store.release("k", successor)  # the real holder still can
        assert await store.get("k") is None

    async def test_stale_complete_cannot_overwrite_a_successors_marker(self, store, redis_client):
        stale = await store.reserve("k")
        await redis_client.delete("idem:k")  # reservation TTL expires mid-call
        assert await store.reserve("k") is not None
        await store.complete("k", {"stale": True}, stale)
        # The successor's reservation must survive the stale write.
        with pytest.raises(IdempotencyConflictError):
            await store.get("k")

    async def test_stale_complete_cannot_overwrite_a_successors_result(self, store, redis_client):
        stale = await store.reserve("k")
        await redis_client.delete("idem:k")  # reservation TTL expires mid-call
        successor = await store.reserve("k")
        await store.complete("k", {"winner": "successor"}, successor)
        await store.complete("k", {"winner": "stale"}, stale)
        assert await store.get("k") == {"winner": "successor"}

    async def test_owner_none_skips_ownership_checks(self, store):
        """Compatibility contract: callers unaware of owner tokens keep the
        pre-token semantics — complete and release act unconditionally."""
        assert await store.reserve("k")
        await store.complete("k", {"ok": True})
        assert await store.get("k") == {"ok": True}
        assert await store.reserve("k2")
        await store.release("k2")
        assert await store.get("k2") is None
        assert await store.reserve("k2") is not None

    async def test_keys_are_independent(self, store):
        await store.reserve("a")
        await store.complete("a", {"n": 1})
        assert await store.reserve("b") is not None
        assert await store.get("a") == {"n": 1}
        with pytest.raises(IdempotencyConflictError):
            await store.get("b")

    async def test_rejects_nonsense_window(self, redis_client):
        with pytest.raises(ValueError):
            IdempotencyStore(redis_client, window_seconds=0)
