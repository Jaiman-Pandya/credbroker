"""Google OAuth 2.0 client: consent URL construction and token endpoint calls.

Security posture: the token endpoint's response carries live credentials, and
its *error* responses can echo back the authorization code or client secret we
sent. Therefore parsed tokens are registered with the log-redaction registry
the moment they exist, and error paths surface only the HTTP status code —
never any part of the response body.
"""

from dataclasses import dataclass
from urllib.parse import urlencode

import httpx

from credbroker.config import Settings
from credbroker.errors import OAuthFlowError
from credbroker.logging_config import register_secret

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
DEFAULT_SCOPES = ["https://www.googleapis.com/auth/drive.readonly"]


@dataclass
class TokenResponse:
    """Parsed token-endpoint payload.

    ``access_token`` and ``refresh_token`` are raw provider credentials: they
    must be envelope-encrypted before storage and must never be logged or
    returned to a caller. Both are registered with the redaction registry
    before a TokenResponse is constructed.
    """

    access_token: str
    refresh_token: str | None
    expires_in: int | None
    scopes: list[str]


def _redirect_uri(settings: Settings) -> str:
    return f"{settings.public_base_url}/oauth/google/callback"


def build_authorize_url(settings: Settings, state: str) -> str:
    """Build the Google consent-screen URL for the connect flow.

    ``access_type=offline`` + ``prompt=consent`` ask Google to issue a refresh
    token even when the user has previously approved this client; without a
    refresh token the connected account dies with its first access token.
    """
    params = {
        "client_id": settings.google_client_id,
        "redirect_uri": _redirect_uri(settings),
        "response_type": "code",
        "scope": " ".join(DEFAULT_SCOPES),
        "state": state,
        "access_type": "offline",
        "prompt": "consent",
    }
    return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"


def _parse_token_response(response: httpx.Response) -> TokenResponse:
    """Parse a token-endpoint response, leaking nothing from the body on error."""
    if response.status_code < 200 or response.status_code >= 300:
        # The body may echo the code or client secret; report only the status.
        raise OAuthFlowError(
            f"google token endpoint returned HTTP {response.status_code}"
        )
    try:
        payload = response.json()
    except ValueError:
        raise OAuthFlowError("google token endpoint returned a non-JSON response") from None

    access_token = payload.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise OAuthFlowError("google token endpoint response is missing access_token")
    refresh_token = payload.get("refresh_token") or None

    # Defense in depth: make the raw credentials unloggable immediately.
    register_secret(access_token)
    register_secret(refresh_token)

    expires_in = payload.get("expires_in")
    expires_in = int(expires_in) if expires_in is not None else None
    scopes = str(payload.get("scope", "")).split()
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=expires_in,
        scopes=scopes,
    )


async def exchange_code(
    http_client: httpx.AsyncClient, settings: Settings, code: str
) -> TokenResponse:
    """Exchange an authorization code for tokens.

    Raises OAuthFlowError on any non-2xx or malformed response, carrying only
    the HTTP status — never the response body.
    """
    response = await http_client.post(
        GOOGLE_TOKEN_URL,
        data={
            "client_id": settings.google_client_id,
            "client_secret": settings.google_client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": _redirect_uri(settings),
        },
    )
    return _parse_token_response(response)


async def refresh_access_token(
    http_client: httpx.AsyncClient, settings: Settings, refresh_token: str
) -> TokenResponse:
    """Redeem a refresh token for a fresh access token.

    Google normally omits ``refresh_token`` from refresh responses, so the
    returned TokenResponse usually has ``refresh_token=None``; callers must
    keep the stored refresh token in that case.
    """
    response = await http_client.post(
        GOOGLE_TOKEN_URL,
        data={
            "client_id": settings.google_client_id,
            "client_secret": settings.google_client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        },
    )
    return _parse_token_response(response)
