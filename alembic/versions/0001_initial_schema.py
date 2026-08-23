"""Initial schema: connected_accounts, agents, grants, tool_call_audit_log.

Revision ID: 0001
Revises:
Create Date: 2026-08-22
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "connected_accounts",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.Text(), nullable=False),
        sa.Column("encrypted_access_token", sa.LargeBinary(), nullable=False),
        sa.Column("encrypted_refresh_token", sa.LargeBinary(), nullable=True),
        sa.Column("scopes_granted", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_connected_accounts_user_id", "connected_accounts", ["user_id"]
    )

    op.create_table(
        "agents",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("allowed_scopes", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_agents_user_id", "agents", ["user_id"])

    op.create_table(
        "grants",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("agent_id", sa.Uuid(), sa.ForeignKey("agents.id"), nullable=False),
        sa.Column(
            "connected_account_id",
            sa.Uuid(),
            sa.ForeignKey("connected_accounts.id"),
            nullable=False,
        ),
        sa.Column("tool_name", sa.Text(), nullable=False),
        sa.Column("scope", sa.Text(), nullable=False),
        sa.Column("grant_token_hash", sa.Text(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_grants_agent_id", "grants", ["agent_id"])
    op.create_index(
        "ix_grants_grant_token_hash", "grants", ["grant_token_hash"], unique=True
    )

    op.create_table(
        "tool_call_audit_log",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("grant_id", sa.Uuid(), sa.ForeignKey("grants.id"), nullable=False),
        sa.Column("tool_name", sa.Text(), nullable=False),
        sa.Column("arguments_hash", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=False),
        sa.Column("called_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_tool_call_audit_log_grant_id", "tool_call_audit_log", ["grant_id"])
    op.create_index("ix_tool_call_audit_log_called_at", "tool_call_audit_log", ["called_at"])


def downgrade() -> None:
    op.drop_table("tool_call_audit_log")
    op.drop_table("grants")
    op.drop_table("agents")
    op.drop_table("connected_accounts")
