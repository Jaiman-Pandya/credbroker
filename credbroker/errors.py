"""Broker error hierarchy.

Every error here carries a message that is safe to surface to a caller:
no raw credentials, no decrypted material, no provider response bodies that
could embed secrets.
"""


class CredBrokerError(Exception):
    """Base class for errors that are safe to surface to callers."""


class UnknownAgentError(CredBrokerError):
    pass


class UnknownToolError(CredBrokerError):
    pass


class PolicyDeniedError(CredBrokerError):
    pass


class GrantScopeMismatchError(CredBrokerError):
    pass


class NoConnectedAccountError(CredBrokerError):
    pass


class ConcurrencyLimitError(CredBrokerError):
    pass


class RateLimitedError(CredBrokerError):
    pass


class GrantNotFoundError(CredBrokerError):
    pass


class GrantExpiredError(CredBrokerError):
    pass


class GrantRevokedError(CredBrokerError):
    pass


class GrantTokenInvalidError(CredBrokerError):
    pass


class IdempotencyConflictError(CredBrokerError):
    pass


class ProviderUnavailableError(CredBrokerError):
    pass


class ProviderCallError(CredBrokerError):
    """A provider API call failed. Carries the HTTP status for retry decisions."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class OAuthFlowError(CredBrokerError):
    pass
