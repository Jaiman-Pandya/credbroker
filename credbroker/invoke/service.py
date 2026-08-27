"""Tool invocation: the security-critical path of the broker.

``InvokeService.invoke`` is the only place a raw provider credential is ever
decrypted, and it enforces every check standing between an agent's grant
token and a real provider API call, in a fixed order:

1.  Offline verification of the RS256 grant token (signature, issuer, expiry).
2.  The requested tool must match the tool the token was issued for.
3.  Revocation and expiry, read from the grant row in the database.
4.  Tool resolution and grant-scope / tool-scope agreement.
5.  Idempotency: replay a cached result without touching the provider, or
    reserve the key for this call.
6.  Connected-account freshness (refreshing the provider access token when
    it has expired — or is about to — and a refresh token is stored).
7.  Decryption of the access token, kept in the narrowest possible scope —
    never stored on the service, never logged, never put in an exception.
8.  The outbound provider call, plus at most one credential refresh and
    retry when the provider rejects a token that looked fresh with a 401.

Every outcome that resolved a real grant row — success, failed, or denied —
writes exactly one audit row. Outcomes reached before a grant row could be
resolved (bad token, tool mismatch, unknown token hash) are logged as
warnings only, since there is no grant to attribute them to. An unexpected
exception after grant resolution never escapes: it is logged server-side
(type name plus scrubbed message), audited, and reported to the agent as a
generic failure — gRPC would otherwise ship ``str(exc)`` to the agent.
"""

import asyncio
import logging
import time
from dataclasses import dataclass
from datetime import timedelta

import httpx
from botocore.exceptions import ClientError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from credbroker.config import Settings
from credbroker.crypto.kms import TokenCipher
from credbroker.db.models import ConnectedAccount, Grant, ensure_aware, utcnow
from credbroker.errors import (
    GrantExpiredError,
    GrantTokenInvalidError,
    IdempotencyConflictError,
    OAuthFlowError,
    ProviderCallError,
    UnknownToolError,
)
from credbroker.grants.tokens import hash_token, verify_grant_token
from credbroker.invoke.audit import record_call
from credbroker.logging_config import scrub
from credbroker.oauth import google
from credbroker.reliability.idempotency import IdempotencyStore
from credbroker.tools import get_tool

logger = logging.getLogger(__name__)

# Refresh a credential that expires this soon, not only one already expired:
# an access token that lapses between the freshness check and the provider
# call (clock skew, transit time) would otherwise surface as a provider 401.
REFRESH_EXPIRY_MARGIN = timedelta(seconds=60)


@dataclass
class InvokeOutcome:
    """The result of one invocation attempt, safe to hand back to an agent.

    ``error`` is always a scrubbed, credential-free message (None on
    success); ``result`` is the provider's JSON-safe payload on success.
    ``denied_reason`` is a machine-readable code set on every denied outcome
    — one of ``invalid_token``, ``expired``, ``revoked``, ``not_found``,
    ``tool_mismatch``, ``scope_mismatch``, ``idempotency_conflict`` — and
    None otherwise.
    """

    status: str  # "success" | "failed" | "denied"
    result: dict | None
    error: str | None  # safe message, scrubbed; None on success
    latency_ms: int
    from_cache: bool = False  # served from idempotency cache
    denied_reason: str | None = None


def _elapsed_ms(start: float) -> int:
    return max(0, int((time.monotonic() - start) * 1000))


class InvokeService:
    """Executes tool calls under grant tokens; the sole holder of decrypted credentials.

    All collaborators are injected. The Redis-backed ``idempotency_store``
    is optional: without it the dedup step is skipped, but every
    database-backed security check still runs.

    ``http_client`` is likewise optional: when omitted, the service lazily
    creates an ``httpx.AsyncClient`` on first use and owns it — call
    :meth:`aclose` on shutdown to close an owned client. An injected client
    always remains the caller's to close.
    """

    def __init__(
        self,
        *,
        settings: Settings,
        session_factory,
        cipher: TokenCipher,
        idempotency_store: IdempotencyStore | None = None,
        http_client: httpx.AsyncClient | None = None,
    ):
        self._settings = settings
        self._session_factory = session_factory
        self._cipher = cipher
        self._idempotency_store = idempotency_store
        self._http_client = http_client
        self._owns_http_client = False

    async def aclose(self) -> None:
        """Close the HTTP client if this service created (and thus owns) it."""
        if self._owns_http_client and self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None
            self._owns_http_client = False

    async def invoke(
        self,
        *,
        grant_token: str,
        tool_name: str,
        arguments: dict,
        idempotency_key: str | None = None,
    ) -> InvokeOutcome:
        """Run one tool invocation under a grant token.

        Never raises for a deniable or failed call — every resolvable
        condition becomes an :class:`InvokeOutcome` (and, once a grant row
        has been resolved, an audit row). Even an unexpected exception after
        grant resolution is converted to a generic, audited failure rather
        than propagating toward the agent.
        """
        start = time.monotonic()

        # Step 1: offline token verification. No grant row is resolvable on
        # failure, so log a warning instead of writing an audit row.
        try:
            claims = verify_grant_token(grant_token, self._settings)
        except GrantExpiredError as exc:
            logger.warning("invoke denied before grant resolution: %s", exc)
            return self._outcome("denied", error=str(exc), denied_reason="expired", start=start)
        except GrantTokenInvalidError as exc:
            logger.warning("invoke denied before grant resolution: %s", exc)
            return self._outcome(
                "denied", error=str(exc), denied_reason="invalid_token", start=start
            )

        # Step 2: the token authorizes exactly one tool.
        if tool_name != claims.tool_name:
            logger.warning(
                "invoke denied: grant %s is bound to tool %r, request named %r",
                claims.grant_id,
                claims.tool_name,
                tool_name,
            )
            return self._outcome(
                "denied",
                error="grant token is not valid for this tool",
                denied_reason="tool_mismatch",
                start=start,
            )

        token_hash = hash_token(grant_token)
        async with self._session_factory() as session:
            grant = (
                await session.execute(select(Grant).where(Grant.grant_token_hash == token_hash))
            ).scalar_one_or_none()
            if grant is None:
                # Verified signature but no row: a foreign-environment token
                # or a lost row. Nothing to audit against.
                logger.warning(
                    "invoke denied: no grant row for presented token (jti=%s)", claims.grant_id
                )
                return self._outcome(
                    "denied", error="grant not found", denied_reason="not_found", start=start
                )

            # Captured before any rollback below could expire the ORM object.
            grant_id = grant.id
            try:
                outcome = await self._invoke_resolved(
                    session=session,
                    grant=grant,
                    tool_name=tool_name,
                    arguments=arguments,
                    idempotency_key=idempotency_key,
                    start=start,
                )
            except Exception as exc:
                # Final backstop: an unexpected error must still be audited,
                # and only a generic message may travel toward the agent
                # (grpc.aio forwards str(exc) verbatim). Server-side, log the
                # type name plus a scrubbed message — never a traceback line
                # that could embed credential material past the filter.
                logger.error(
                    "unexpected error invoking %s under grant %s: %s: %s",
                    tool_name,
                    grant_id,
                    type(exc).__name__,
                    scrub(str(exc)),
                )
                # The session may hold a broken transaction; clear it so the
                # audit write below can still commit.
                await session.rollback()
                outcome = self._outcome(
                    "failed", error="internal error during tool invocation", start=start
                )

            # Step 9: exactly one audit row per outcome with a resolved grant.
            await record_call(
                session,
                grant_id=grant_id,
                tool_name=tool_name,
                arguments=arguments,
                status=outcome.status,
                latency_ms=outcome.latency_ms,
            )
        return outcome

    async def _invoke_resolved(
        self,
        *,
        session: AsyncSession,
        grant: Grant,
        tool_name: str,
        arguments: dict,
        idempotency_key: str | None,
        start: float,
    ) -> InvokeOutcome:
        """Steps 3 through 8, once a grant row exists to audit against."""
        # Step 3: revocation and grant expiry, straight from the grant row.
        if grant.revoked_at is not None:
            return self._outcome(
                "denied", error="grant has been revoked", denied_reason="revoked", start=start
            )
        if ensure_aware(grant.expires_at) <= utcnow():
            return self._outcome(
                "denied", error="grant has expired", denied_reason="expired", start=start
            )

        # Step 4: tool resolution and scope agreement.
        try:
            tool = get_tool(tool_name)
        except UnknownToolError as exc:
            return self._outcome(
                "denied", error=str(exc), denied_reason="not_found", start=start
            )
        if grant.scope != tool.scope:
            return self._outcome(
                "denied",
                error=f"grant scope {grant.scope!r} does not match tool scope {tool.scope!r}",
                denied_reason="scope_mismatch",
                start=start,
            )

        # Step 5: idempotency — replay, conflict, or reservation. The key is
        # bound to the connected account as well as the agent, so a replay
        # can never serve a result produced against a different account.
        full_key: str | None = None
        reservation: str | None = None
        if idempotency_key is not None and self._idempotency_store is not None:
            full_key = (
                f"{grant.agent_id}:{grant.connected_account_id}:{tool_name}:{idempotency_key}"
            )
            try:
                cached = await self._idempotency_store.get(full_key)
            except IdempotencyConflictError:
                return self._outcome(
                    "denied",
                    error="concurrent call with same idempotency key",
                    denied_reason="idempotency_conflict",
                    start=start,
                )
            if cached is not None:
                return self._outcome("success", result=cached, start=start, from_cache=True)
            reservation = await self._idempotency_store.reserve(full_key)
            if reservation is None:
                # Lost a race between get() and reserve(): someone else now
                # holds the key. Same conflict, later detection.
                return self._outcome(
                    "denied",
                    error="concurrent call with same idempotency key",
                    denied_reason="idempotency_conflict",
                    start=start,
                )

        try:
            outcome = await self._execute_call(
                session=session,
                grant=grant,
                tool=tool,
                arguments=arguments,
                start=start,
            )
        except Exception:
            # An unexpected error must not wedge the idempotency key for the
            # full reservation TTL; free it, then let the error surface. The
            # owner token stops a stale holder (reservation TTL expired
            # mid-call) from clobbering a successor's reservation or result.
            if full_key is not None:
                await self._idempotency_store.release(full_key, owner=reservation)
            raise

        if full_key is not None:
            if outcome.status == "success":
                await self._idempotency_store.complete(
                    full_key, outcome.result or {}, owner=reservation
                )
            else:
                await self._idempotency_store.release(full_key, owner=reservation)
        return outcome

    async def _execute_call(
        self,
        *,
        session: AsyncSession,
        grant: Grant,
        tool,
        arguments: dict,
        start: float,
    ) -> InvokeOutcome:
        """Steps 6-8: account freshness, decryption, and the provider call."""
        # Step 6: load the backing account and refresh its credential if stale.
        account = await session.get(ConnectedAccount, grant.connected_account_id)
        if account is None:
            return self._outcome("failed", error="connected account no longer exists", start=start)

        # Step 7: the decrypted credential lives only in these locals and the
        # tool-call closure — never on self, never in a log line, never
        # inside an exception message.
        expires_at = ensure_aware(account.expires_at)
        refreshed = False
        access_token: str | None = None
        if expires_at is not None and expires_at <= utcnow() + REFRESH_EXPIRY_MARGIN:
            if self._can_refresh(account):
                refresh_result = await self._refresh_or_outcome(session, account, start)
                if isinstance(refresh_result, InvokeOutcome):
                    return refresh_result
                access_token = refresh_result
                refreshed = True
            elif expires_at <= utcnow():
                return self._outcome(
                    "failed",
                    error="connected account credential has expired and cannot be refreshed",
                    start=start,
                )
            # Inside the margin but unrefreshable: the stored token is still
            # valid, so fall through and use it.
        if access_token is None:
            try:
                # Cipher calls may block on a synchronous KMS round trip;
                # keep them off the event loop.
                access_token = await asyncio.to_thread(
                    self._cipher.decrypt, account.encrypted_access_token
                )
            except (ClientError, ValueError):
                # ValueError: corrupt blob (TokenCipher). ClientError: the
                # KMS Decrypt call failed — kms.py deliberately lets it
                # propagate. Either way the stored credential is unusable.
                return self._outcome(
                    "failed", error="stored credential could not be decrypted", start=start
                )

        # Step 8: the provider call. One in-band recovery: a 401 on a
        # credential this call has not already refreshed triggers a single
        # refresh and retry (the token may have been invalidated
        # provider-side); a second 401 fails.
        while True:
            try:
                result = await self._call_provider(tool, access_token, arguments)
            except ProviderCallError as exc:
                if exc.status_code == 401 and not refreshed and self._can_refresh(account):
                    refresh_result = await self._refresh_or_outcome(session, account, start)
                    if isinstance(refresh_result, InvokeOutcome):
                        return refresh_result
                    access_token = refresh_result
                    refreshed = True
                    continue
                # Carries a caller-safe message by construction (status only).
                return self._outcome("failed", error=str(exc), start=start)
            except httpx.TimeoutException:
                return self._outcome(
                    "failed", error=f"{tool.name} timed out contacting the provider", start=start
                )
            except httpx.TransportError:
                # Transport errors can embed URLs/hosts; report a generic message.
                return self._outcome(
                    "failed", error=f"{tool.name} could not reach the provider", start=start
                )
            except ValueError:
                # e.g. a JSON parse failure on the provider's response; the
                # body is not under our control, so never surface str(exc).
                return self._outcome(
                    "failed", error=f"{tool.name} returned a malformed response", start=start
                )
            return self._outcome("success", result=result, start=start)

    async def _call_provider(self, tool, access_token: str, arguments: dict) -> dict:
        """Run one outbound provider call."""
        return await tool.call(access_token, arguments, self._http())

    async def _refresh_or_outcome(
        self, session: AsyncSession, account: ConnectedAccount, start: float
    ) -> str | InvokeOutcome:
        """Refresh ``account``'s credential, mapping every failure to a failed outcome.

        On success the rotated credential is already persisted and the new
        plaintext access token is returned; callers must keep its scope as
        small as possible. No failure mode surfaces raw exception text.
        """
        try:
            return await self._refresh_credential(session, account)
        except OAuthFlowError as exc:
            # OAuthFlowError messages carry only an HTTP status by contract.
            return self._outcome(
                "failed", error=f"credential refresh failed: {exc}", start=start
            )
        except httpx.HTTPError:
            # Transport errors can embed URLs/hosts; never forward str(exc).
            return self._outcome(
                "failed",
                error="credential refresh failed: could not reach the token endpoint",
                start=start,
            )
        except (ClientError, ValueError):
            return self._outcome(
                "failed", error="stored credential could not be decrypted", start=start
            )

    async def _refresh_credential(
        self, session: AsyncSession, account: ConnectedAccount
    ) -> str:
        """Redeem the stored refresh token and persist the rotated credential.

        Commits the re-encrypted access token (and rotated refresh token,
        when the provider returns one) before handing back the plaintext,
        which the OAuth client has already registered with the log-redaction
        registry. Cipher calls may block on a synchronous KMS round trip, so
        they run in a thread.
        """
        refresh_token = await asyncio.to_thread(
            self._cipher.decrypt, account.encrypted_refresh_token
        )
        refreshed = await google.refresh_access_token(self._http(), self._settings, refresh_token)
        account.encrypted_access_token = await asyncio.to_thread(
            self._cipher.encrypt, refreshed.access_token
        )
        if refreshed.refresh_token:
            # Rare: Google rotated the refresh token; keep the new one.
            account.encrypted_refresh_token = await asyncio.to_thread(
                self._cipher.encrypt, refreshed.refresh_token
            )
        account.expires_at = (
            utcnow() + timedelta(seconds=refreshed.expires_in)
            if refreshed.expires_in is not None
            else None
        )
        await session.commit()
        return refreshed.access_token

    @staticmethod
    def _can_refresh(account: ConnectedAccount) -> bool:
        """Whether the account's credential is refreshable (v1 refreshes Google only)."""
        return account.encrypted_refresh_token is not None and account.provider == "google"

    def _http(self) -> httpx.AsyncClient:
        """Return the HTTP client, lazily creating an owned one when none was injected."""
        if self._http_client is None:
            # Created here, owned here: aclose() closes it. An injected
            # client is never closed by this service.
            self._http_client = httpx.AsyncClient(timeout=15.0)
            self._owns_http_client = True
        return self._http_client

    def _outcome(
        self,
        status: str,
        *,
        result: dict | None = None,
        error: str | None = None,
        denied_reason: str | None = None,
        start: float,
        from_cache: bool = False,
    ) -> InvokeOutcome:
        """Build an outcome, scrubbing the error message as belt-and-braces.

        Error strings on these paths are constructed to be safe already;
        scrubbing against the secret registry guarantees that even a message
        assembled from an unexpected source cannot carry a registered
        credential out of the broker.
        """
        return InvokeOutcome(
            status=status,
            result=result,
            error=scrub(error) if error is not None else None,
            latency_ms=_elapsed_ms(start),
            from_cache=from_cache,
            denied_reason=denied_reason,
        )
