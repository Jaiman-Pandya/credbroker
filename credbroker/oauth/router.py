"""HTTP routes for the OAuth connect flow.

Dependencies come off ``request.app.state`` (settings, session_factory,
cipher, http_client) exactly as wired by :func:`credbroker.app.create_app`.

v1 identity model: the end user is identified solely by the ``user_id`` query
parameter on the authorize endpoint — real end-user authentication (a login
session in front of this flow) is out of scope for v1. The state parameter's
HMAC still binds the callback to the user_id the flow started with, so the
callback cannot be replayed for a different user.
"""

import asyncio
import logging
import re
import uuid
from datetime import timedelta

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from credbroker import metrics
from credbroker.db.models import ConnectedAccount, utcnow
from credbroker.errors import OAuthFlowError
from credbroker.oauth import google
from credbroker.oauth.state import make_state, verify_state

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/oauth", tags=["oauth"])

_PROVIDER = "google"


def _require_google(provider: str) -> None:
    """404 for any provider we do not support (v1: Google only)."""
    if provider != _PROVIDER:
        raise HTTPException(status_code=404, detail=f"unknown provider: {provider}")


@router.get("/{provider}/authorize")
async def authorize(provider: str, user_id: uuid.UUID, request: Request) -> RedirectResponse:
    """Redirect the user's browser to the provider consent screen.

    ``user_id`` is required and must be a UUID (FastAPI rejects anything else
    with a 422 before this body runs).
    """
    _require_google(provider)
    settings = request.app.state.settings
    state = make_state(settings, str(user_id))
    return RedirectResponse(google.build_authorize_url(settings, state), status_code=307)


@router.get("/{provider}/callback")
async def callback(
    provider: str,
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> dict:
    """Complete the connect flow: verify state, exchange the code, store tokens.

    The tokens are envelope-encrypted before they touch the database, and the
    response identifies the connected account without ever containing them.
    """
    _require_google(provider)
    settings = request.app.state.settings

    if error is not None:
        # The provider redirected back with an RFC 6749 error (most commonly
        # access_denied when the user declines consent). Echo only a vetted
        # error token, never arbitrary caller-controlled text.
        safe_error = error if re.fullmatch(r"[a-z_]{1,64}", error) else "unknown_error"
        raise HTTPException(status_code=400, detail=f"provider reported: {safe_error}")
    if code is None or state is None:
        raise HTTPException(status_code=422, detail="missing code or state parameter")

    try:
        user_id = uuid.UUID(verify_state(settings, state))
        token = await google.exchange_code(request.app.state.http_client, settings, code)
    except OAuthFlowError as exc:
        # CredBrokerError messages are safe by construction; str(exc) carries
        # no state payload, no authorization code, and no provider body.
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except ValueError:
        # A verified state whose payload is not a UUID: signed by us but not
        # minted by the authorize endpoint above.
        raise HTTPException(status_code=400, detail="oauth state carries no valid user id") from None

    cipher = request.app.state.cipher
    # Envelope encryption can call out to KMS synchronously; keep it off the
    # event loop.
    encrypted_access = await asyncio.to_thread(cipher.encrypt, token.access_token)
    encrypted_refresh = (
        await asyncio.to_thread(cipher.encrypt, token.refresh_token)
        if token.refresh_token
        else None
    )
    account = ConnectedAccount(
        user_id=user_id,
        provider=_PROVIDER,
        encrypted_access_token=encrypted_access,
        encrypted_refresh_token=encrypted_refresh,
        scopes_granted=token.scopes,
        expires_at=(
            utcnow() + timedelta(seconds=token.expires_in)
            if token.expires_in is not None
            else None
        ),
    )
    async with request.app.state.session_factory() as session:
        session.add(account)
        await session.flush()
        account_id = account.id
        await session.commit()

    metrics.OAUTH_ACCOUNTS_CONNECTED.labels(provider=_PROVIDER).inc()
    logger.info("connected %s account %s for user %s", _PROVIDER, account_id, user_id)
    return {
        "connected_account_id": str(account_id),
        "provider": _PROVIDER,
        "scopes": token.scopes,
    }
