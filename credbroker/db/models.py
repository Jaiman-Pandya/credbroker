"""SQLAlchemy models for the broker's PostgreSQL schema.

Scope arrays are text[] on PostgreSQL and JSON on SQLite (used only in tests).
All timestamps are timezone-aware UTC; SQLite drops tzinfo on read, so any
comparison against a column value must go through ensure_aware().
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, LargeBinary, Text, Uuid
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

StringArray = ARRAY(Text).with_variant(JSON(), "sqlite")


def utcnow() -> datetime:
    return datetime.now(UTC)


def ensure_aware(dt: datetime | None) -> datetime | None:
    """Normalize a timestamp read from the DB to timezone-aware UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


class Base(DeclarativeBase):
    pass


class ConnectedAccount(Base):
    """A user's real provider account; tokens are KMS-envelope-encrypted at rest."""

    __tablename__ = "connected_accounts"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    provider: Mapped[str] = mapped_column(Text, nullable=False)
    encrypted_access_token: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encrypted_refresh_token: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    scopes_granted: Mapped[list[str]] = mapped_column(StringArray, nullable=False, default=list)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class AgentIdentity(Base):
    """An agent identity and the policy of scopes it may ever request.

    An agent acts on behalf of exactly one user; grant issuance only ever
    binds it to that user's connected accounts. Without this binding a grant
    would silently attach to whichever account was connected most recently —
    by anyone.
    """

    __tablename__ = "agents"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    allowed_scopes: Mapped[list[str]] = mapped_column(StringArray, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class Grant(Base):
    """A short-lived, scope-limited authorization issued to an agent.

    Only the SHA-256 hash of the grant token is stored; possession of the DB
    contents is not possession of a usable token.
    """

    __tablename__ = "grants"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    agent_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("agents.id"), nullable=False, index=True
    )
    connected_account_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("connected_accounts.id"), nullable=False
    )
    tool_name: Mapped[str] = mapped_column(Text, nullable=False)
    scope: Mapped[str] = mapped_column(Text, nullable=False)
    grant_token_hash: Mapped[str] = mapped_column(Text, nullable=False, unique=True, index=True)
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ToolCallAuditLog(Base):
    """One row per attempted tool invocation: who, what, when, result."""

    __tablename__ = "tool_call_audit_log"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    grant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("grants.id"), nullable=False, index=True
    )
    tool_name: Mapped[str] = mapped_column(Text, nullable=False)
    arguments_hash: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)  # success / failed / denied
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    called_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
