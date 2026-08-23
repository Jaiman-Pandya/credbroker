"""Envelope encryption for stored provider credentials.

Raw OAuth tokens are encrypted at rest with a fresh AES-256-GCM data key per
value; the data key itself is wrapped by a key manager (AWS KMS in
production, a local AES-256-GCM master key in dev/test). Only the invoke and
oauth services ever see plaintext, and every decrypted value is registered
with the log-redaction filter.
"""

from credbroker.crypto.kms import (
    AwsKmsKeyManager,
    KeyManager,
    LocalKeyManager,
    TokenCipher,
    build_token_cipher,
)

__all__ = [
    "AwsKmsKeyManager",
    "KeyManager",
    "LocalKeyManager",
    "TokenCipher",
    "build_token_cipher",
]
