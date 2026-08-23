"""KMS-style envelope encryption for provider credentials.

Every stored credential is encrypted under a *fresh* 256-bit data key
(AES-256-GCM), and the data key is wrapped by a :class:`KeyManager` — AWS KMS
in production, or a local master key for dev/test. Compromise of one
ciphertext therefore never exposes a key that protects any other value, and
rotating the KMS key re-protects all data keys without re-encrypting rows.

Blob layout (versioned, all lengths in bytes)::

    b"CB1" | len(encrypted_key) as u16 big-endian | encrypted_key
          | 12-byte nonce | AES-GCM ciphertext (includes 16-byte tag)

Security invariants enforced here:

* :meth:`TokenCipher.decrypt` registers every plaintext with
  :func:`credbroker.logging_config.register_secret` before returning it, so
  the redaction filter scrubs it from any log line.
* Corrupt, truncated, or unknown-version blobs raise :class:`ValueError`;
  error messages never include key or plaintext material.
"""

import base64
import logging
import os
import struct
from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from credbroker.config import Settings
from credbroker.logging_config import register_secret

logger = logging.getLogger(__name__)

_MAGIC = b"CB1"
_KEY_LEN_STRUCT = struct.Struct(">H")
_NONCE_SIZE = 12
_GCM_TAG_SIZE = 16
_DATA_KEY_SIZE = 32
_HEADER_SIZE = len(_MAGIC) + _KEY_LEN_STRUCT.size


class KeyManager(Protocol):
    """Wraps and unwraps per-value data keys under a long-lived master key."""

    def generate_data_key(self) -> tuple[bytes, bytes]:
        """Return ``(plaintext_key, encrypted_key_blob)`` for a fresh 32-byte key."""
        ...

    def decrypt_data_key(self, encrypted_key_blob: bytes) -> bytes:
        """Unwrap an encrypted data key back to its 32-byte plaintext."""
        ...


class AwsKmsKeyManager:
    """Key manager backed by AWS KMS (GenerateDataKey / Decrypt, AES_256).

    The boto3 client is injectable for tests; when omitted, a real client is
    constructed for ``region``. ``key_id`` is passed on Decrypt as well as
    GenerateDataKey so a blob wrapped under a different CMK is rejected.
    """

    def __init__(self, key_id: str, region: str, client=None):
        if client is None:
            import boto3

            client = boto3.client("kms", region_name=region)
        self._key_id = key_id
        self._client = client

    def generate_data_key(self) -> tuple[bytes, bytes]:
        """Ask KMS for a fresh AES-256 data key; returns (plaintext, ciphertext blob)."""
        response = self._client.generate_data_key(KeyId=self._key_id, KeySpec="AES_256")
        return response["Plaintext"], response["CiphertextBlob"]

    def decrypt_data_key(self, encrypted_key_blob: bytes) -> bytes:
        """Unwrap a KMS-encrypted data key. KMS errors propagate as-is."""
        response = self._client.decrypt(
            KeyId=self._key_id, CiphertextBlob=encrypted_key_blob
        )
        return response["Plaintext"]


class LocalKeyManager:
    """Dev/test key manager: wraps data keys with AES-256-GCM under a local master key.

    Never use in production — the master key lives in process memory and in
    configuration. Wrapped-key layout: 12-byte nonce followed by the GCM
    ciphertext of the data key.
    """

    def __init__(self, master_key: bytes):
        if len(master_key) != _DATA_KEY_SIZE:
            raise ValueError(
                f"local master key must be {_DATA_KEY_SIZE} bytes, got {len(master_key)}"
            )
        self._master = AESGCM(master_key)

    def generate_data_key(self) -> tuple[bytes, bytes]:
        """Generate a random 32-byte data key and wrap it under the master key."""
        plaintext_key = os.urandom(_DATA_KEY_SIZE)
        nonce = os.urandom(_NONCE_SIZE)
        wrapped = nonce + self._master.encrypt(nonce, plaintext_key, None)
        return plaintext_key, wrapped

    def decrypt_data_key(self, encrypted_key_blob: bytes) -> bytes:
        """Unwrap a data key; raises ValueError on corruption or a wrong master key."""
        if len(encrypted_key_blob) < _NONCE_SIZE + _GCM_TAG_SIZE:
            raise ValueError("encrypted data key is truncated")
        nonce = encrypted_key_blob[:_NONCE_SIZE]
        wrapped = encrypted_key_blob[_NONCE_SIZE:]
        try:
            return self._master.decrypt(nonce, wrapped, None)
        except InvalidTag:
            raise ValueError("failed to unwrap data key (corrupt blob or wrong master key)") from None


class TokenCipher:
    """Envelope-encrypts credential strings using a fresh data key per value."""

    def __init__(self, key_manager: KeyManager):
        self._key_manager = key_manager

    def encrypt(self, plaintext: str) -> bytes:
        """Encrypt ``plaintext`` under a brand-new data key; returns a versioned blob.

        The plaintext is registered for log redaction here too — any caller
        holding a raw credential has already touched it.
        """
        register_secret(plaintext)
        data_key, encrypted_key = self._key_manager.generate_data_key()
        if len(encrypted_key) > 0xFFFF:
            raise ValueError("encrypted data key too large for blob format")
        nonce = os.urandom(_NONCE_SIZE)
        ciphertext = AESGCM(data_key).encrypt(nonce, plaintext.encode("utf-8"), None)
        return (
            _MAGIC
            + _KEY_LEN_STRUCT.pack(len(encrypted_key))
            + encrypted_key
            + nonce
            + ciphertext
        )

    def decrypt(self, blob: bytes) -> str:
        """Decrypt a blob produced by :meth:`encrypt`.

        Raises ValueError on an unknown version or any corrupt/truncated blob.
        The recovered plaintext is registered with the redaction filter before
        it is returned; callers must keep its scope as small as possible.
        """
        if len(blob) < _HEADER_SIZE:
            raise ValueError("credential blob is truncated")
        if blob[: len(_MAGIC)] != _MAGIC:
            raise ValueError("unknown credential blob version")
        (key_len,) = _KEY_LEN_STRUCT.unpack_from(blob, len(_MAGIC))
        body_start = _HEADER_SIZE + key_len
        if len(blob) < body_start + _NONCE_SIZE + _GCM_TAG_SIZE:
            raise ValueError("credential blob is truncated")
        encrypted_key = blob[_HEADER_SIZE:body_start]
        nonce = blob[body_start : body_start + _NONCE_SIZE]
        ciphertext = blob[body_start + _NONCE_SIZE :]
        data_key = self._key_manager.decrypt_data_key(encrypted_key)
        try:
            plaintext_bytes = AESGCM(data_key).decrypt(nonce, ciphertext, None)
        except InvalidTag:
            raise ValueError("credential blob failed authentication (corrupt)") from None
        plaintext = plaintext_bytes.decode("utf-8")
        register_secret(plaintext)
        return plaintext


def build_token_cipher(settings: Settings) -> TokenCipher:
    """Construct the TokenCipher selected by configuration.

    ``kms_key_id`` set selects AWS KMS. Otherwise the local key manager is
    used with ``local_master_key_b64``; if that is empty too, an ephemeral
    random master key is generated (dev only — nothing encrypted under it
    survives a restart) and a warning is logged.
    """
    if settings.kms_key_id:
        return TokenCipher(AwsKmsKeyManager(settings.kms_key_id, settings.aws_region))
    if settings.local_master_key_b64:
        master_key = base64.b64decode(settings.local_master_key_b64)
    else:
        logger.warning(
            "no KMS key or local master key configured; using an ephemeral master key "
            "(dev only — encrypted credentials will not survive a restart)"
        )
        master_key = os.urandom(_DATA_KEY_SIZE)
    return TokenCipher(LocalKeyManager(master_key))
