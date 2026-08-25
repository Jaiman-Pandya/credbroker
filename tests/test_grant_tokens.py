"""Tests for grant token signing, verification, and hashing."""

import base64
import hashlib
import json
import uuid
from datetime import timedelta

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from credbroker.db.models import utcnow
from credbroker.errors import GrantExpiredError, GrantTokenInvalidError
from credbroker.grants.tokens import (
    GrantClaims,
    hash_token,
    sign_grant_token,
    verify_grant_token,
)


def _sign(settings, **overrides):
    now = utcnow()
    kwargs = {
        "settings": settings,
        "grant_id": uuid.uuid4(),
        "agent_id": uuid.uuid4(),
        "tool_name": "drive.read",
        "scope": "read",
        "issued_at": now,
        "expires_at": now + timedelta(seconds=300),
    }
    kwargs.update(overrides)
    return kwargs, sign_grant_token(**kwargs)


def test_sign_verify_roundtrip(settings):
    kwargs, token = _sign(settings)

    claims = verify_grant_token(token, settings)

    assert isinstance(claims, GrantClaims)
    assert claims.grant_id == kwargs["grant_id"]
    assert claims.agent_id == kwargs["agent_id"]
    assert claims.tool_name == "drive.read"
    assert claims.scope == "read"


def test_expired_token_raises_grant_expired(settings):
    now = utcnow()
    _, token = _sign(
        settings,
        issued_at=now - timedelta(seconds=600),
        expires_at=now - timedelta(seconds=300),
    )

    with pytest.raises(GrantExpiredError):
        verify_grant_token(token, settings)


def test_tampered_payload_raises_invalid(settings):
    _, token = _sign(settings)
    header_b64, payload_b64, sig_b64 = token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
    payload["scope"] = "write"  # privilege escalation attempt
    forged_payload = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).rstrip(b"=").decode()
    forged = f"{header_b64}.{forged_payload}.{sig_b64}"

    with pytest.raises(GrantTokenInvalidError):
        verify_grant_token(forged, settings)


def test_wrong_key_raises_invalid(settings):
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_private_pem = other_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    rogue_settings = settings.model_copy(update={"jwt_private_key_pem": other_private_pem})
    _, token = _sign(rogue_settings)

    with pytest.raises(GrantTokenInvalidError):
        verify_grant_token(token, settings)


def test_wrong_issuer_raises_invalid(settings):
    rogue_settings = settings.model_copy(update={"jwt_issuer": "not-credbroker"})
    _, token = _sign(rogue_settings)

    with pytest.raises(GrantTokenInvalidError):
        verify_grant_token(token, settings)


def test_garbage_token_raises_invalid(settings):
    with pytest.raises(GrantTokenInvalidError):
        verify_grant_token("not-a-jwt-at-all", settings)


def test_missing_claims_raises_invalid(settings):
    # A structurally valid, correctly signed JWT that lacks the broker claims.
    token = pyjwt.encode(
        {
            "iss": settings.jwt_issuer,
            "sub": str(uuid.uuid4()),
            "jti": "not-a-uuid",
            "iat": int(utcnow().timestamp()),
            "exp": int((utcnow() + timedelta(seconds=300)).timestamp()),
        },
        settings.jwt_private_key_pem,
        algorithm="RS256",
    )

    with pytest.raises(GrantTokenInvalidError):
        verify_grant_token(token, settings)


def test_hash_token_is_sha256_hexdigest():
    token = "some.grant.token"
    assert hash_token(token) == hashlib.sha256(token.encode()).hexdigest()
    assert hash_token(token) == hash_token(token)
    assert hash_token(token) != hash_token(token + "x")
