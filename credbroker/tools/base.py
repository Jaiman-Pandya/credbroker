"""Tool adapter interface and registry.

A tool adapter receives a decrypted access token for the duration of one call
and must never persist, log, or return it. The invoke service is the only
caller; it owns the HTTP client and the decrypted token's lifetime.
"""

import abc

import httpx

from credbroker.config import Settings
from credbroker.errors import UnknownToolError


class ToolAdapter(abc.ABC):
    """One class of provider action, e.g. 'drive.read'."""

    name: str  # tool identifier agents request, e.g. "drive.read"
    provider: str  # connected-account provider, e.g. "google"
    scope: str  # action class: "read" or "write"
    side_effectful: bool  # True if the call mutates provider state

    # Deliberately a concrete no-op, not @abstractmethod: most adapters need
    # no configuration and must not be forced to override it.
    def configure(self, settings: Settings) -> None:  # noqa: B027
        """Apply settings to this adapter; a no-op by default.

        Called once at process startup (see
        :func:`credbroker.tools.configure_tools`). Adapters whose endpoint is
        configurable override this; an unconfigured adapter must behave
        exactly as it did before this hook existed.
        """

    @abc.abstractmethod
    async def call(
        self, access_token: str, arguments: dict, http_client: httpx.AsyncClient
    ) -> dict:
        """Execute the provider API call and return a JSON-safe result dict."""


TOOL_REGISTRY: dict[str, ToolAdapter] = {}


def register_tool(tool: ToolAdapter) -> None:
    TOOL_REGISTRY[tool.name] = tool


def get_tool(name: str) -> ToolAdapter:
    try:
        return TOOL_REGISTRY[name]
    except KeyError:
        raise UnknownToolError(f"unknown tool: {name}") from None
