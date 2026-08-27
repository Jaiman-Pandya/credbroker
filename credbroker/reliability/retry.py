"""Retry and circuit-breaking for outbound provider calls.

The broker sits between agents and provider APIs, so a flaky provider must
degrade gracefully: transient transport failures and provider 5xx responses
are retried with exponential backoff, while a persistently failing provider
trips a circuit breaker so we stop hammering it (and stop burning latency
budget on calls that cannot succeed).

Both the clock and the sleep function are injectable so tests are fully
deterministic — no real time passes in the test suite. Nothing in this module
ever touches a raw provider credential; it only drives opaque zero-argument
async callables supplied by the caller.
"""

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from credbroker.errors import ProviderCallError, ProviderUnavailableError

_CLOSED = "closed"
_OPEN = "open"
_HALF_OPEN = "half_open"


class CircuitBreaker:
    """Classic closed / open / half-open circuit breaker.

    - **closed**: calls flow; consecutive retryable failures are counted.
      Reaching ``failure_threshold`` trips the circuit open.
    - **open**: :meth:`allow` returns ``False`` until ``reset_seconds`` have
      elapsed on the injected monotonic clock.
    - **half_open**: after the reset window exactly one probe call is
      allowed through; further calls are rejected (as if open) until the
      probe records. A recorded success closes the circuit, a recorded
      failure re-opens it for another full ``reset_seconds`` window.

    A recorded success always resets the consecutive-failure count, so only
    an unbroken run of failures can trip the circuit. State transitions are
    driven lazily off the clock — the breaker holds no timers of its own.
    """

    def __init__(
        self,
        failure_threshold: int,
        reset_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ):
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        if reset_seconds < 0:
            raise ValueError("reset_seconds must be >= 0")
        self._failure_threshold = failure_threshold
        self._reset_seconds = reset_seconds
        self._clock = clock
        self._state = _CLOSED
        self._consecutive_failures = 0
        self._opened_at: float | None = None
        self._probe_in_flight = False

    def _sync(self) -> None:
        """Move open -> half_open once the reset window has elapsed."""
        if self._state == _OPEN and self._opened_at is not None:
            if self._clock() - self._opened_at >= self._reset_seconds:
                self._state = _HALF_OPEN
                self._probe_in_flight = False

    @property
    def state(self) -> str:
        """Current state: ``"closed"``, ``"open"``, or ``"half_open"``."""
        self._sync()
        return self._state

    def allow(self) -> bool:
        """Return whether a call may proceed right now.

        While half-open the first caller claims the single probe slot;
        until that probe records a success or failure, every other call is
        rejected exactly as if the circuit were still open.
        """
        self._sync()
        if self._state == _OPEN:
            return False
        if self._state == _HALF_OPEN:
            if self._probe_in_flight:
                return False
            self._probe_in_flight = True
        return True

    def record_success(self) -> None:
        """Note a successful call: close the circuit and reset the count."""
        self._state = _CLOSED
        self._consecutive_failures = 0
        self._opened_at = None
        self._probe_in_flight = False

    def record_failure(self) -> None:
        """Note a failed call, tripping the circuit at the threshold.

        A failure while half-open re-opens immediately; a failure reported
        while already open (a straggler call that started earlier) re-arms
        the reset window.
        """
        self._sync()
        if self._state == _CLOSED:
            self._consecutive_failures += 1
            if self._consecutive_failures >= self._failure_threshold:
                self._trip()
        else:  # half_open probe failed, or straggler failure while open
            self._trip()

    def _trip(self) -> None:
        self._state = _OPEN
        self._opened_at = self._clock()
        self._probe_in_flight = False


def default_retryable(exc: Exception) -> bool:
    """Default retry predicate for provider calls.

    Retryable: httpx timeouts and transport-level failures, and
    :class:`ProviderCallError` carrying a 5xx status. Everything else —
    notably provider 4xx responses, which will not improve on retry — is not.
    """
    if isinstance(exc, httpx.TimeoutException | httpx.TransportError):
        return True
    if isinstance(exc, ProviderCallError):
        return exc.status_code is not None and exc.status_code >= 500
    return False


async def call_with_retries(
    fn: Callable[[], Awaitable[Any]],
    *,
    max_retries: int,
    base_delay: float,
    circuit: CircuitBreaker | None = None,
    retryable: Callable[[Exception], bool] = default_retryable,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> Any:
    """Await ``fn()`` with exponential backoff and optional circuit breaking.

    Makes at most ``1 + max_retries`` attempts, sleeping
    ``base_delay * 2**attempt`` between them (via the injectable ``sleep``,
    so tests never really wait). Behavior:

    - If ``circuit`` is open when an attempt would start, raise
      :class:`ProviderUnavailableError` without calling ``fn`` at all.
    - A failure for which ``retryable`` returns ``False`` (e.g. a provider
      4xx) is re-raised immediately and does **not** trip the circuit — the
      provider is healthy, the request is just bad.
    - Retryable failures are recorded on the circuit; once retries are
      exhausted the last exception is re-raised.
    - Success records on the circuit and returns ``fn()``'s result.
    """
    if max_retries < 0:
        raise ValueError("max_retries must be >= 0")
    if base_delay < 0:
        raise ValueError("base_delay must be >= 0")

    for attempt in range(max_retries + 1):
        if circuit is not None and not circuit.allow():
            raise ProviderUnavailableError(
                "provider temporarily unavailable (circuit breaker open)"
            )
        try:
            result = await fn()
        except Exception as exc:
            if not retryable(exc):
                raise
            if circuit is not None:
                circuit.record_failure()
            if attempt >= max_retries:
                raise
            await sleep(base_delay * 2**attempt)
        else:
            if circuit is not None:
                circuit.record_success()
            return result
    raise AssertionError("unreachable")  # pragma: no cover
