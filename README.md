# CredBroker

A scoped credential broker for MCP tool calls. CredBroker sits between agents
and the real APIs their tools call. Agents never hold raw OAuth credentials —
they request short-lived, scoped grants, and the broker executes the actual
API call on their behalf, auditing every action.

**Core principle: credentials never leave the broker.**

Work in progress — see `docs/DESIGN.md` for the design and build plan.
