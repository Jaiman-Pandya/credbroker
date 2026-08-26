"""Audit logging for tool invocations.

Every invocation that resolves to a real grant row — whether it succeeds,
fails, or is denied — produces exactly one row in ``tool_call_audit_log``:
who (via the grant), what (tool + argument hash), when, and the result.

Only a SHA-256 hash of the call arguments is persisted, never the arguments
themselves: argument payloads are caller-controlled and could contain
sensitive material, while a canonical hash is still enough to prove after the
fact that a specific call was (or was not) made with specific inputs. Raw
provider credentials never reach this module at all.
"""

import hashlib
import json
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from credbroker.db.models import ToolCallAuditLog


def hash_arguments(arguments: dict) -> str:
    """Return the canonical SHA-256 hex digest of a call's arguments.

    The dict is serialized with sorted keys and compact separators so the
    same logical arguments always hash identically regardless of insertion
    order, making audit rows comparable across retries and replicas.
    """
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def record_call(
    session: AsyncSession,
    *,
    grant_id: uuid.UUID,
    tool_name: str,
    arguments: dict,
    status: str,
    latency_ms: int,
) -> ToolCallAuditLog:
    """Persist one audit row for an attempted tool invocation and commit.

    Commits immediately so the audit trail is durable even if the caller's
    surrounding work is later rolled back or the process dies. ``status`` is
    one of ``"success"``, ``"failed"``, or ``"denied"``.
    """
    row = ToolCallAuditLog(
        grant_id=grant_id,
        tool_name=tool_name,
        arguments_hash=hash_arguments(arguments),
        status=status,
        latency_ms=latency_ms,
    )
    session.add(row)
    await session.commit()
    return row
