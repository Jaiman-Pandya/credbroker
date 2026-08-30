"""Idempotent seed data for credential-free demos.

Creates one demo user, one agent identity allowed to use ``drive.read``, and
one connected Google account. The stored access token is a fixed placeholder
string — envelope-encrypted at rest exactly like a real credential, but only
the fake Drive provider (:mod:`credbroker.demo.fake_drive`) will ever accept
it, so pointing the broker at the real Google API with this seed simply 401s.

The account's ``expires_at`` sits a year out so the invoke path's freshness
check never tries to refresh (there is no refresh token to redeem).
"""

import asyncio
import uuid
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from credbroker.crypto.kms import TokenCipher
from credbroker.db.models import AgentIdentity, ConnectedAccount, utcnow

DEMO_AGENT_NAME = "demo agent"
DEMO_PROVIDER = "google"
# Deliberately shaped like a label, not a secret: this string only ever
# authenticates against the local fake Drive provider.
DEMO_ACCESS_TOKEN = "demo-access-token-not-a-real-credential"


async def seed_demo(session: AsyncSession, cipher: TokenCipher) -> dict:
    """Create (or find) the demo agent and its connected account.

    Idempotent by agent name: the first call creates the rows and reports
    ``created: True``; later calls reuse them and report ``created: False``.
    A missing account behind an existing agent (e.g. a partially wiped demo
    database) is recreated rather than left broken.
    """
    created = False
    agent = (
        await session.execute(select(AgentIdentity).where(AgentIdentity.name == DEMO_AGENT_NAME))
    ).scalar_one_or_none()
    if agent is None:
        agent = AgentIdentity(
            user_id=uuid.uuid4(), name=DEMO_AGENT_NAME, allowed_scopes=["drive.read"]
        )
        session.add(agent)
        await session.flush()
        created = True

    account = (
        await session.execute(
            select(ConnectedAccount)
            .where(
                ConnectedAccount.user_id == agent.user_id,
                ConnectedAccount.provider == DEMO_PROVIDER,
            )
            .order_by(ConnectedAccount.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if account is None:
        # Envelope encryption can call out to KMS synchronously; keep it off
        # the event loop (matches the OAuth callback's handling).
        encrypted_access = await asyncio.to_thread(cipher.encrypt, DEMO_ACCESS_TOKEN)
        account = ConnectedAccount(
            user_id=agent.user_id,
            provider=DEMO_PROVIDER,
            encrypted_access_token=encrypted_access,
            encrypted_refresh_token=None,
            scopes_granted=["demo"],
            expires_at=utcnow() + timedelta(days=365),
        )
        session.add(account)
        await session.flush()
        created = True

    # Capture ids before commit: with an expiring session the ORM objects
    # would otherwise need a refresh to be read afterwards.
    payload = {
        "user_id": str(agent.user_id),
        "agent_id": str(agent.id),
        "connected_account_id": str(account.id),
        "created": created,
    }
    await session.commit()
    return payload
