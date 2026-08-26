"""Tool invocation path: grant verification through audited provider calls.

The invoke service is the only component that ever decrypts a raw provider
credential, and it does so for exactly one call at a time, inside the
narrowest possible scope. Everything an agent gets back is an
:class:`~credbroker.invoke.service.InvokeOutcome` — a status, a JSON-safe
result, and a scrubbed error message — never credential material.
"""

from credbroker.invoke.audit import hash_arguments, record_call
from credbroker.invoke.service import InvokeOutcome, InvokeService

__all__ = ["InvokeOutcome", "InvokeService", "hash_arguments", "record_call"]
