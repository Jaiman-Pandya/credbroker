"""Grant issuance: short-lived, scope-limited signed tokens for agents.

Agents never receive raw provider credentials. They receive an RS256-signed
JWT ("grant token") that authorizes one tool + scope for a few minutes, and
the broker keeps only the SHA-256 hash of that token at rest.
"""

from credbroker.grants.service import IssuedGrant, request_grant, revoke_grant
from credbroker.grants.tokens import (
    GrantClaims,
    hash_token,
    sign_grant_token,
    verify_grant_token,
)

__all__ = [
    "GrantClaims",
    "IssuedGrant",
    "hash_token",
    "request_grant",
    "revoke_grant",
    "sign_grant_token",
    "verify_grant_token",
]
