"""Operator web console: a small REST API plus a static single-page UI.

The console is an operator-facing surface for demos and day-to-day
inspection: list tools, agents, accounts, grants, and audit rows; issue and
revoke grants; and invoke tools by playing the agent role. It reuses the
same grant and invoke services as the gRPC surface, so every security check
applies unchanged — and, like every other surface, it never exposes
encrypted token blobs, decrypted credentials, or JWT keys.
"""
