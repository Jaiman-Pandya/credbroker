"""Stateless CSRF protection for the OAuth redirect dance.

The ``state`` parameter round-trips through the user's browser and the
provider, so it must be tamper-evident without requiring server-side session
storage. Format (before urlsafe base64):

    ``user_id|expiry_epoch|nonce|hmac_sha256_hexdigest``

The digest is keyed with ``settings.oauth_state_secret`` over the
``user_id|expiry_epoch|nonce`` payload. The expiry is baked in at mint time
(``oauth_state_ttl_seconds``) and covered by the signature, so a caller cannot
extend a state's lifetime. The nonce makes every state unique; it carries no
meaning on verification.
"""

import base64
import binascii
import hashlib
import hmac
import secrets
import time

from credbroker.config import Settings
from credbroker.errors import OAuthFlowError

_NONCE_BYTES = 16


def _sign(secret: str, payload: str) -> str:
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


def make_state(settings: Settings, user_id: str) -> str:
    """Mint a signed state parameter binding this flow to ``user_id``.

    ``user_id`` must not contain ``|`` (it is a UUID string in practice).
    """
    if "|" in user_id:
        raise ValueError("user_id must not contain '|'")
    expiry_epoch = int(time.time()) + settings.oauth_state_ttl_seconds
    nonce = secrets.token_hex(_NONCE_BYTES)
    payload = f"{user_id}|{expiry_epoch}|{nonce}"
    signed = f"{payload}|{_sign(settings.oauth_state_secret, payload)}"
    return base64.urlsafe_b64encode(signed.encode()).decode()


def verify_state(settings: Settings, state: str) -> str:
    """Verify a state parameter and return the user_id it was minted for.

    Raises OAuthFlowError on malformed input, a bad signature, or expiry.
    The signature is checked before the expiry so an attacker learns nothing
    from forged payloads, and compared in constant time.
    """
    try:
        decoded = base64.urlsafe_b64decode(state.encode()).decode()
    except (binascii.Error, UnicodeDecodeError, ValueError):
        raise OAuthFlowError("malformed oauth state") from None

    parts = decoded.split("|")
    if len(parts) != 4:
        raise OAuthFlowError("malformed oauth state")
    user_id, expiry_str, nonce, signature = parts

    expected = _sign(settings.oauth_state_secret, f"{user_id}|{expiry_str}|{nonce}")
    # Compare as bytes: compare_digest raises TypeError on non-ASCII str input,
    # which a crafted state could otherwise turn into an unhandled 500.
    if not hmac.compare_digest(signature.encode(), expected.encode()):
        raise OAuthFlowError("oauth state signature mismatch")

    try:
        expiry_epoch = int(expiry_str)
    except ValueError:
        raise OAuthFlowError("malformed oauth state") from None
    if time.time() > expiry_epoch:
        raise OAuthFlowError("oauth state expired")

    return user_id
