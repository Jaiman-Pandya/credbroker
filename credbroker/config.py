"""Application settings.

Everything is overridable via CREDBROKER_* environment variables (or a local
.env file in development). Services receive a Settings instance explicitly —
modules must not read the environment at import time.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CREDBROKER_", env_file=".env", extra="ignore")

    # Core services
    database_url: str = "postgresql+asyncpg://credbroker:credbroker@localhost:5432/credbroker"
    redis_url: str = "redis://localhost:6379/0"
    http_host: str = "0.0.0.0"
    http_port: int = 8000
    grpc_port: int = 50051
    public_base_url: str = "http://localhost:8000"

    # OAuth providers
    google_client_id: str = ""
    google_client_secret: str = ""
    oauth_state_secret: str = "dev-state-secret-not-for-production"
    oauth_state_ttl_seconds: int = 600

    # Credential encryption (envelope encryption via KMS)
    kms_key_id: str = ""  # empty selects the local key manager (dev/test only)
    aws_region: str = "us-east-1"
    local_master_key_b64: str = ""  # base64-encoded 32-byte key for the local key manager

    # Grant tokens
    grant_token_ttl_seconds: int = 300
    jwt_private_key_pem: str = ""
    jwt_public_key_pem: str = ""
    jwt_issuer: str = "credbroker"
    max_active_grants_per_agent_scope: int = 1

    # Idempotency
    idempotency_window_seconds: int = 3600


@lru_cache
def get_settings() -> Settings:
    return Settings()
