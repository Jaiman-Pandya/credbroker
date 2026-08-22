# CredBroker — Design

A broker service that sits between agents and the real APIs their MCP tools
call (Google Drive, Slack, GitHub, …). Agents never hold raw OAuth
credentials. Instead, they request short-lived, scoped grants from the broker,
and the broker executes the actual API call on their behalf, logging every
action.

Core principle: **credentials never leave the broker.** Agents only ever hold
time-boxed, scope-limited grant tokens that authorize one class of action, not
the underlying secret itself.

## Goals

- Users connect real accounts (Google, Slack, GitHub) via standard OAuth once;
  the broker stores and manages the tokens.
- An agent requests a grant for a specific tool + scope and gets a short-lived
  signed token, not the raw credential.
- The broker proxies the actual tool call, so raw credentials are never
  transmitted to or logged by the agent.
- Every grant issuance and tool call is audited: who, what, when, result.
- Grants expire automatically and can be revoked mid-flight.

## Non-goals (v1)

- Supporting every OAuth provider. Start with Google, prove the pattern,
  generalize later.
- Fine-grained per-field scoping. v1 scopes per tool ("can call `drive.read`"),
  not per resource.
- Multi-region deployment.

## Architecture

- **Broker service:** FastAPI + gRPC. gRPC for agent-facing grant/invoke
  calls; REST only for the OAuth redirect dance, since browsers need HTTP.
- **Credential storage:** PostgreSQL, envelope-encrypted via AWS KMS.
- **Grant cache / rate limiting:** Redis (ElastiCache in AWS).
- **Deployment:** ECS Fargate + RDS + ElastiCache, Terraform-managed,
  GitHub Actions CI/CD.
- **Observability:** Prometheus metrics, Grafana dashboard (grant issuance
  rate, invoke latency, failure rate, revocations).

## Data model

Four tables. See `credbroker/db/models.py` and the Alembic migrations for the
authoritative definitions.

- `connected_accounts` — a user's real provider account. Access/refresh tokens
  are stored KMS-envelope-encrypted (`bytea`); the plaintext exists only
  transiently inside the invoke path.
- `agents` — an agent identity plus `allowed_scopes`, the policy of what this
  identity is ever permitted to request. Every agent belongs to exactly one
  user (`user_id`); grants only ever bind to that user's connected accounts,
  so one tenant's agents can never spend another tenant's credentials.
- `grants` — one short-lived authorization. Stores the SHA-256 **hash** of the
  grant token, never the token itself; `revoked_at` supports immediate kill.
- `tool_call_audit_log` — one row per attempted invocation: tool, argument
  hash (not raw args), status (success/failed/denied), latency.

## Scope model

- `tool_name` identifies a class of action against a provider, e.g.
  `drive.read`. Each tool adapter declares its provider (`google`) and its
  action class (`read`/`write`).
- `agents.allowed_scopes` holds tool names the agent may request.
- A grant binds (agent, connected account, tool, scope) for a short TTL
  (default 5 minutes).

## Credential flow

1. User connects Google via `/oauth/google/authorize` → consent →
   `/oauth/google/callback`. The broker exchanges the code for tokens,
   envelope-encrypts them with KMS, and stores them in `connected_accounts`.
2. Agent calls `RequestGrant(agent_id, tool_name, requested_scope)`.
3. Broker checks `agents.allowed_scopes`, issues a signed JWT grant token
   (RS256, 5-minute TTL), stores its hash in `grants`.
4. Agent calls `InvokeTool(grant_token, tool_name, arguments, idempotency_key)`.
5. Broker validates the token (signature, expiry, not revoked), decrypts the
   real credential internally, makes the provider API call, writes an audit
   row, and returns only the result.
6. The agent-facing code path never carries a raw OAuth token.

## Safe execution

- **Idempotency:** side-effectful invokes carry an idempotency key; the broker
  deduplicates retries within a time window (Redis-backed).
- **Retry/backoff:** outbound provider calls get exponential backoff on
  5xx/timeouts, a capped retry count, and a circuit breaker per provider.
- **Grant races:** concurrent `RequestGrant` calls for the same agent+scope
  are serialized with a DB row lock on the agent before the active-grant count
  is enforced — not just an application-level check.
- **Revocation propagation:** revocation writes both the DB (`revoked_at`) and
  a Redis revocation marker; `InvokeTool` checks revocation again immediately
  before the outbound call so an in-flight invoke is killed too.

## Build order

1. Schema + migrations
2. OAuth connect flow (Google) with real KMS envelope encryption
3. `RequestGrant` with policy check, signed JWT
4. `InvokeTool` proxying one real call (Drive list files)
5. Audit log writes on every invoke
6. Idempotency + retry/backoff
7. Redis grant cache + rate limiting
8. Docker, Terraform, GitHub Actions
9. Prometheus + Grafana
10. Security regression tests: expired grant rejected, revoked grant rejected
    immediately, raw token never in any log line or response
