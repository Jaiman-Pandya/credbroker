"""Prometheus metrics.

Instrumented at the request boundaries (gRPC servicer, OAuth router) where
outcomes are known, so business logic stays free of metrics plumbing.
"""

from prometheus_client import Counter, Histogram

GRANTS_ISSUED = Counter(
    "credbroker_grants_issued_total",
    "Grants issued, by tool and scope",
    ["tool_name", "scope"],
)
GRANT_DENIALS = Counter(
    "credbroker_grant_denials_total",
    "Grant requests denied, by reason",
    ["reason"],
)
GRANTS_REVOKED = Counter(
    "credbroker_grants_revoked_total",
    "Grants revoked",
)
INVOCATIONS = Counter(
    "credbroker_tool_invocations_total",
    "Tool invocations, by tool and outcome status",
    ["tool_name", "status"],
)
INVOKE_LATENCY = Histogram(
    "credbroker_invoke_latency_seconds",
    "End-to-end InvokeTool latency",
    ["tool_name"],
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)
OAUTH_ACCOUNTS_CONNECTED = Counter(
    "credbroker_accounts_connected_total",
    "Provider accounts connected via OAuth",
    ["provider"],
)
RATE_LIMITED = Counter(
    "credbroker_rate_limited_total",
    "Requests rejected by rate limiting, by operation",
    ["operation"],
)
