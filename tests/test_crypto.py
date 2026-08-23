"""Tests for KMS envelope encryption (credbroker.crypto.kms).

Everything runs offline: the local key manager exercises the real AES-GCM
path, and the AWS key manager is driven through a hand-rolled stub client
(no moto, no network).
"""

import base64
import os
import struct

import pytest

from credbroker import logging_config
from credbroker.crypto.kms import (
    AwsKmsKeyManager,
    LocalKeyManager,
    TokenCipher,
    build_token_cipher,
)

PLAINTEXT = "ya29.raw-google-access-token-value"


@pytest.fixture
def master_key() -> bytes:
    return os.urandom(32)


@pytest.fixture
def cipher(master_key) -> TokenCipher:
    return TokenCipher(LocalKeyManager(master_key))


@pytest.fixture(autouse=True)
def _clean_secret_registry():
    """Isolate the redaction registry so assertions about it are exact."""
    logging_config.clear_registry()
    yield
    logging_config.clear_registry()


class RecordingKeyManager:
    """Wraps a real key manager, recording every data key it hands out."""

    def __init__(self, inner):
        self._inner = inner
        self.data_keys: list[bytes] = []
        self.encrypted_keys: list[bytes] = []

    def generate_data_key(self):
        plaintext_key, encrypted_key = self._inner.generate_data_key()
        self.data_keys.append(plaintext_key)
        self.encrypted_keys.append(encrypted_key)
        return plaintext_key, encrypted_key

    def decrypt_data_key(self, encrypted_key_blob):
        return self._inner.decrypt_data_key(encrypted_key_blob)


class StubKmsClient:
    """Minimal boto3 KMS client stand-in: XOR-'wraps' keys, records calls."""

    def __init__(self):
        self.generate_calls: list[dict] = []
        self.decrypt_calls: list[dict] = []
        self._pad = os.urandom(32)

    def _wrap(self, key: bytes) -> bytes:
        return b"stub:" + bytes(a ^ b for a, b in zip(key, self._pad, strict=True))

    def generate_data_key(self, *, KeyId, KeySpec):
        self.generate_calls.append({"KeyId": KeyId, "KeySpec": KeySpec})
        key = os.urandom(32)
        return {"Plaintext": key, "CiphertextBlob": self._wrap(key), "KeyId": KeyId}

    def decrypt(self, *, KeyId, CiphertextBlob):
        self.decrypt_calls.append({"KeyId": KeyId, "CiphertextBlob": CiphertextBlob})
        assert CiphertextBlob.startswith(b"stub:")
        wrapped = CiphertextBlob[len(b"stub:") :]
        key = bytes(a ^ b for a, b in zip(wrapped, self._pad, strict=True))
        return {"Plaintext": key, "KeyId": KeyId}


class TestLocalKeyManager:
    def test_master_key_must_be_32_bytes(self):
        with pytest.raises(ValueError):
            LocalKeyManager(b"short")
        with pytest.raises(ValueError):
            LocalKeyManager(os.urandom(33))

    def test_data_key_roundtrip(self, master_key):
        km = LocalKeyManager(master_key)
        plaintext_key, wrapped = km.generate_data_key()
        assert len(plaintext_key) == 32
        assert wrapped != plaintext_key
        assert km.decrypt_data_key(wrapped) == plaintext_key

    def test_wrong_master_key_fails_to_unwrap(self, master_key):
        _, wrapped = LocalKeyManager(master_key).generate_data_key()
        other = LocalKeyManager(os.urandom(32))
        with pytest.raises(ValueError):
            other.decrypt_data_key(wrapped)

    def test_truncated_wrapped_key_rejected(self, master_key):
        km = LocalKeyManager(master_key)
        _, wrapped = km.generate_data_key()
        with pytest.raises(ValueError):
            km.decrypt_data_key(wrapped[:10])


class TestTokenCipher:
    def test_roundtrip(self, cipher):
        blob = cipher.encrypt(PLAINTEXT)
        assert isinstance(blob, bytes)
        assert cipher.decrypt(blob) == PLAINTEXT

    def test_blob_format(self, cipher):
        blob = cipher.encrypt(PLAINTEXT)
        assert blob[:3] == b"CB1"
        (key_len,) = struct.unpack_from(">H", blob, 3)
        # header + wrapped key + nonce + ciphertext(+tag) accounts for every byte
        assert len(blob) == 3 + 2 + key_len + 12 + len(PLAINTEXT.encode()) + 16
        assert PLAINTEXT.encode() not in blob

    def test_fresh_data_key_and_unique_ciphertext_per_call(self, master_key):
        recorder = RecordingKeyManager(LocalKeyManager(master_key))
        cipher = TokenCipher(recorder)
        blobs = [cipher.encrypt(PLAINTEXT) for _ in range(3)]
        assert len(recorder.data_keys) == 3
        assert len(set(recorder.data_keys)) == 3, "data key must be fresh per encryption"
        assert len(set(recorder.encrypted_keys)) == 3
        assert len(set(blobs)) == 3, "identical plaintexts must yield distinct blobs"
        for blob in blobs:
            assert cipher.decrypt(blob) == PLAINTEXT

    def test_unknown_version_rejected(self, cipher):
        blob = cipher.encrypt(PLAINTEXT)
        with pytest.raises(ValueError):
            cipher.decrypt(b"CB9" + blob[3:])

    def test_corrupt_ciphertext_rejected(self, cipher):
        blob = bytearray(cipher.encrypt(PLAINTEXT))
        blob[-1] ^= 0x01  # flip a bit in the GCM tag / ciphertext tail
        with pytest.raises(ValueError):
            cipher.decrypt(bytes(blob))

    def test_corrupt_wrapped_key_rejected(self, cipher):
        blob = bytearray(cipher.encrypt(PLAINTEXT))
        blob[6] ^= 0x01  # inside the encrypted data key section
        with pytest.raises(ValueError):
            cipher.decrypt(bytes(blob))

    def test_truncated_blob_rejected(self, cipher):
        blob = cipher.encrypt(PLAINTEXT)
        for cut in (0, 2, 4, len(blob) // 2, len(blob) - 1):
            with pytest.raises(ValueError):
                cipher.decrypt(blob[:cut])

    def test_wrong_master_key_cannot_decrypt(self, cipher):
        blob = cipher.encrypt(PLAINTEXT)
        other = TokenCipher(LocalKeyManager(os.urandom(32)))
        with pytest.raises(ValueError):
            other.decrypt(blob)

    def test_decrypt_registers_secret_for_redaction(self, cipher):
        blob = cipher.encrypt("super-secret-token-abc123")
        logging_config.clear_registry()  # encrypt() registered it too; start clean
        assert logging_config.scrub("x super-secret-token-abc123 y") == "x super-secret-token-abc123 y"
        recovered = cipher.decrypt(blob)
        scrubbed = logging_config.scrub(f"leaked: {recovered}")
        assert recovered not in scrubbed
        assert logging_config.REDACTED in scrubbed

    def test_encrypt_registers_secret_too(self, cipher):
        cipher.encrypt("another-secret-token-xyz")
        assert "another-secret-token-xyz" not in logging_config.scrub("another-secret-token-xyz")


class TestAwsKmsKeyManager:
    def test_generate_uses_aes_256_keyspec_and_pins_key_id(self):
        stub = StubKmsClient()
        km = AwsKmsKeyManager("alias/credbroker", "us-east-1", client=stub)
        plaintext_key, wrapped = km.generate_data_key()
        assert stub.generate_calls == [{"KeyId": "alias/credbroker", "KeySpec": "AES_256"}]
        assert len(plaintext_key) == 32
        assert km.decrypt_data_key(wrapped) == plaintext_key
        assert stub.decrypt_calls[0]["KeyId"] == "alias/credbroker"

    def test_token_cipher_over_stub_kms(self):
        stub = StubKmsClient()
        cipher = TokenCipher(AwsKmsKeyManager("alias/credbroker", "us-east-1", client=stub))
        blob = cipher.encrypt(PLAINTEXT)
        assert cipher.decrypt(blob) == PLAINTEXT
        assert len(stub.generate_calls) == 1
        assert len(stub.decrypt_calls) == 1


class TestBuildTokenCipher:
    def test_kms_key_id_selects_aws(self, settings):
        aws_settings = settings.model_copy(update={"kms_key_id": "alias/credbroker"})
        cipher = build_token_cipher(aws_settings)
        assert isinstance(cipher._key_manager, AwsKmsKeyManager)

    def test_local_master_key_selects_local(self, settings):
        cipher = build_token_cipher(settings)
        assert isinstance(cipher._key_manager, LocalKeyManager)
        # Two ciphers built from the same settings share the master key,
        # so blobs are interchangeable between them.
        other = build_token_cipher(settings)
        assert other.decrypt(cipher.encrypt(PLAINTEXT)) == PLAINTEXT

    def test_empty_master_key_generates_ephemeral_and_warns(self, settings, caplog):
        bare = settings.model_copy(update={"kms_key_id": "", "local_master_key_b64": ""})
        with caplog.at_level("WARNING", logger="credbroker.crypto.kms"):
            cipher = build_token_cipher(bare)
        assert any("ephemeral" in rec.message for rec in caplog.records)
        assert cipher.decrypt(cipher.encrypt(PLAINTEXT)) == PLAINTEXT
        # A second build gets a *different* ephemeral key.
        with pytest.raises(ValueError):
            build_token_cipher(bare).decrypt(cipher.encrypt(PLAINTEXT))

    def test_invalid_master_key_length_rejected(self, settings):
        bad = settings.model_copy(
            update={"local_master_key_b64": base64.b64encode(b"too-short").decode()}
        )
        with pytest.raises(ValueError):
            build_token_cipher(bad)
