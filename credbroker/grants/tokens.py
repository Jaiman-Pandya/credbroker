"""Grant token signing and verification (RS256 JWTs).

A grant token is the *only* credential an agent ever holds. It is not a raw
provider credential — it is a short-lived capability the broker itself issued
and can verify offline. The broker persists only ``hash_token(token)``, so a
database dump never yields a usable token.

Claims layout:
    iss   settings.jwt_issuer
    sub   agent id (UUID string)
    jti   grant id (UUID string)
    tool  tool name the grant authorizes (e.g. "drive.read")
    scope action class ("read" / "write")
    iat / exp
"""

import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime

import jwt

from credbroker.config import Settings
from credbroker.errors import GrantExpiredError, GrantTokenInvalidError

_ALGORITHM = "RS256"
_REQUIRED_CLAIMS = ["iss", "sub", "jti", "iat", "exp"]


@dataclass
class GrantClaims:
    """Verified claims extracted from a grant token."""

    grant_id: uuid.UUID
    agent_id: uuid.UUID
    tool_name: str
    scope: str


def hash_token(token: str) -> str:
    """SHA-256 hex digest of a grant token — the only form ever stored."""
    return hashlib.sha256(token.encode()).hexdigest()


def sign_grant_token(
    *,
    settings: Settings,
    grant_id: uuid.UUID,
    agent_id: uuid.UUID,
    tool_name: str,
    scope: str,
    issued_at: datetime,
    expires_at: datetime,
) -> str:
    """Sign an RS256 grant token binding (grant, agent, tool, scope) to a TTL."""
    payload = {
        "iss": settings.jwt_issuer,
        "sub": str(agent_id),
        "jti": str(grant_id),
        "tool": tool_name,
        "scope": scope,
        "iat": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    return jwt.encode(payload, settings.jwt_private_key_pem, algorithm=_ALGORITHM)


def verify_grant_token(token: str, settings: Settings) -> GrantClaims:
    """Verify signature, issuer, and expiry; return the token's claims.

    Raises:
        GrantExpiredError: the token's ``exp`` has passed.
        GrantTokenInvalidError: any other failure — bad signature, wrong
            issuer, wrong algorithm, missing or malformed claims.
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt_public_key_pem,
            algorithms=[_ALGORITHM],
            issuer=settings.jwt_issuer,
            options={"require": _REQUIRED_CLAIMS},
        )
    except jwt.ExpiredSignatureError as exc:
        raise GrantExpiredError("grant token has expired") from exc
    except (jwt.PyJWTError, ValueError) as exc:
        # PyJWTError covers InvalidTokenError AND InvalidKeyError (which is not
        # a token error); ValueError covers an unparseable configured PEM key.
        raise GrantTokenInvalidError("grant token is invalid") from exc

    try:
        return GrantClaims(
            grant_id=uuid.UUID(payload["jti"]),
            agent_id=uuid.UUID(payload["sub"]),
            tool_name=str(payload["tool"]),
            scope=str(payload["scope"]),
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise GrantTokenInvalidError("grant token claims are malformed") from exc
