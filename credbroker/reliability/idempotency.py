"""Redis-backed idempotency store for tool invocations.

Agents retry: networks flake, processes crash mid-call. When an agent
supplies an idempotency key, the broker must guarantee the underlying
provider call happens at most once per key within the configured window,
even across concurrent invocations. The protocol:

1. :meth:`IdempotencyStore.get` — a cached result means the call already
   completed; serve it without touching the provider. A pending marker means
   another invocation holds the key mid-flight, which is a conflict.
2. :meth:`IdempotencyStore.reserve` — atomically claim the key (SET NX with
   a short TTL so a crashed holder cannot wedge the key forever). On success
   it returns an opaque owner token identifying this reservation.
3. :meth:`IdempotencyStore.complete` on success — replace the marker with
   the JSON result for the full idempotency window — or
   :meth:`IdempotencyStore.release` on failure, so a retry can proceed.
   Passing the owner token to either makes it a no-op unless this caller
   still holds the reservation: if the TTL expired mid-call and another
   invocation re-reserved the key, a stale holder can no longer delete or
   overwrite the new holder's state. Callers may omit the token (``None``)
   to skip the ownership check, preserving the pre-token behavior.

Ownership checks are GET-compare-then-act, not atomic: a marker that
expires between the compare and the act can still be clobbered. That race
window is milliseconds against a 60-second TTL, so it is accepted rather
than pulling in a Lua script.

Only provider *results* are stored here, never credentials: the invoke path
strips tokens before anything reaches this module.
"""

import json
import secrets

from credbroker.errors import IdempotencyConflictError

# Prefix of the marker stored while a reservation holder is mid-flight; the
# holder's owner token follows it. JSON results always start with "{", so
# the prefix cannot collide with a completed result.
PENDING_MARKER = "__pending__"
# Reservation lifetime: long enough for any sane provider call (including
# retries), short enough that a crashed holder frees the key quickly.
RESERVATION_TTL_SECONDS = 60

_KEY_PREFIX = "idem:"


class IdempotencyStore:
    """At-most-once result cache keyed by caller-supplied idempotency keys.

    Expects an async Redis client created with ``decode_responses=True``
    (values are ``str``). Keys are namespaced under ``idem:`` so they cannot
    collide with grant-cache or rate-limit keys sharing the database.
    """

    def __init__(self, redis, window_seconds: int):
        if window_seconds < 1:
            raise ValueError("window_seconds must be >= 1")
        self._redis = redis
        self._window_seconds = window_seconds

    @staticmethod
    def _name(key: str) -> str:
        return f"{_KEY_PREFIX}{key}"

    @staticmethod
    def _pending_value(owner: str) -> str:
        return f"{PENDING_MARKER}:{owner}"

    async def get(self, key: str) -> dict | None:
        """Return the cached result for ``key``, or ``None`` if unseen.

        Raises :class:`IdempotencyConflictError` if a reservation marker is
        present — another invocation with the same key is mid-flight, and
        running a second provider call concurrently would defeat the
        at-most-once guarantee.
        """
        value = await self._redis.get(self._name(key))
        if value is None:
            return None
        if value.startswith(PENDING_MARKER):
            raise IdempotencyConflictError(
                "a concurrent call with the same idempotency key is in flight"
            )
        return json.loads(value)

    async def reserve(self, key: str) -> str | None:
        """Atomically claim ``key`` with a pending marker (SET NX).

        Returns the reservation's owner token (an opaque non-empty string,
        so truthy) if this caller now holds the reservation, or ``None`` if
        the key already carries a marker or a completed result. Pass the
        token to :meth:`complete` or :meth:`release` so a holder whose
        reservation expired mid-call cannot disturb a successor's state.
        The marker expires after :data:`RESERVATION_TTL_SECONDS` so a
        crashed holder cannot block the key indefinitely.
        """
        owner = secrets.token_hex(16)
        claimed = await self._redis.set(
            self._name(key),
            self._pending_value(owner),
            nx=True,
            ex=RESERVATION_TTL_SECONDS,
        )
        return owner if claimed else None

    async def complete(self, key: str, result: dict, owner: str | None = None) -> None:
        """Replace the pending marker with the JSON result.

        The result stays cached for the store's ``window_seconds`` so agent
        retries within the window are served without a second provider call.
        With ``owner`` given, the write happens only while the key still
        holds this owner's pending marker — a holder whose reservation
        expired and was re-claimed must not overwrite the new holder's
        state. ``owner=None`` skips the check (pre-token behavior).
        """
        name = self._name(key)
        if owner is not None:
            value = await self._redis.get(name)
            if value != self._pending_value(owner):
                return
        await self._redis.set(
            name,
            json.dumps(result),
            ex=self._window_seconds,
        )

    async def release(self, key: str, owner: str | None = None) -> None:
        """Drop the pending marker after a failed call so a retry can proceed.

        Only removes the key while it still holds a pending marker — a
        completed result is never discarded — and, with ``owner`` given,
        only while the marker is this owner's, so a stale holder cannot
        free a key that a successor has re-reserved. ``owner=None`` skips
        the ownership check (pre-token behavior).
        """
        name = self._name(key)
        value = await self._redis.get(name)
        if value is None or not value.startswith(PENDING_MARKER):
            return
        if owner is not None and value != self._pending_value(owner):
            return
        await self._redis.delete(name)
