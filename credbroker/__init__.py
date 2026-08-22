"""CredBroker: a scoped credential broker for MCP tool calls.

Agents never hold raw OAuth credentials. They request short-lived, scoped
grants from the broker, and the broker executes the actual API call on their
behalf, logging every action.
"""

__version__ = "0.1.0"
