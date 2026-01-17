"""Security tests for encryption roundtrip operations.

These tests verify that the CryptoService correctly encrypts and decrypts
data using AES-256-GCM, and that password-based key derivation works
correctly with PBKDF2-HMAC-SHA256.

TDD Note: These tests are written before the CryptoService implementation
and should FAIL until the implementation is complete.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest

from src.core.crypto import CryptoService
from src.models.exceptions import EncryptionError

if TYPE_CHECKING:
    pass


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def crypto_service() -> CryptoService:
    """Create a CryptoService instance for testing."""
    return CryptoService()


@pytest.fixture
def test_password() -> str:
    """Provide a test password."""
    return "TestMasterPassword123!"


@pytest.fixture
def test_salt() -> bytes:
    """Provide a fixed test salt for deterministic testing."""
    return os.urandom(32)


@pytest.fixture
def test_plaintext() -> bytes:
    """Provide test data to encrypt."""
    return b"This is sensitive data that needs to be encrypted securely."


# =============================================================================
# Key Derivation Tests
# =============================================================================


class TestKeyDerivation:
    """Tests for PBKDF2 key derivation."""

    def test_derive_key_returns_32_bytes(
        self, crypto_service: CryptoService, test_password: str, test_salt: bytes
    ) -> None:
        """derive_key should return a 32-byte key (256 bits)."""
        key = crypto_service.derive_key(test_password, test_salt)
        assert len(key) == 32

    def test_derive_key_is_deterministic(
        self, crypto_service: CryptoService, test_password: str, test_salt: bytes
    ) -> None:
        """Same password and salt should produce same key."""
        key1 = crypto_service.derive_key(test_password, test_salt)
        key2 = crypto_service.derive_key(test_password, test_salt)
        assert key1 == key2

    def test_different_passwords_produce_different_keys(
        self, crypto_service: CryptoService, test_salt: bytes
    ) -> None:
        """Different passwords should produce different keys."""
        key1 = crypto_service.derive_key("password1", test_salt)
        key2 = crypto_service.derive_key("password2", test_salt)
        assert key1 != key2

    def test_different_salts_produce_different_keys(
        self, crypto_service: CryptoService, test_password: str
    ) -> None:
        """Different salts should produce different keys."""
        salt1 = os.urandom(32)
        salt2 = os.urandom(32)
        key1 = crypto_service.derive_key(test_password, salt1)
        key2 = crypto_service.derive_key(test_password, salt2)
        assert key1 != key2

    def test_empty_password_still_works(
        self, crypto_service: CryptoService, test_salt: bytes
    ) -> None:
        """Empty password should still produce a key (not recommended but valid)."""
        key = crypto_service.derive_key("", test_salt)
        assert len(key) == 32


# =============================================================================
# Salt Generation Tests
# =============================================================================


class TestSaltGeneration:
    """Tests for cryptographic salt generation."""

    def test_generate_salt_returns_32_bytes(
        self, crypto_service: CryptoService
    ) -> None:
        """generate_salt should return 32 bytes."""
        salt = crypto_service.generate_salt()
        assert len(salt) == 32

    def test_generate_salt_is_random(self, crypto_service: CryptoService) -> None:
        """Each call should produce different salt."""
        salts = [crypto_service.generate_salt() for _ in range(10)]
        # All salts should be unique
        assert len(set(salts)) == 10


# =============================================================================
# Encryption Tests
# =============================================================================


class TestEncryption:
    """Tests for AES-256-GCM encryption."""

    def test_encrypt_produces_output(
        self,
        crypto_service: CryptoService,
        test_password: str,
        test_salt: bytes,
        test_plaintext: bytes,
    ) -> None:
        """encrypt should produce ciphertext."""
        key = crypto_service.derive_key(test_password, test_salt)
        ciphertext = crypto_service.encrypt(test_plaintext, key)
        assert ciphertext is not None
        assert len(ciphertext) > 0

    def test_encrypt_output_differs_from_input(
        self,
        crypto_service: CryptoService,
        test_password: str,
        test_salt: bytes,
        test_plaintext: bytes,
    ) -> None:
        """Ciphertext should differ from plaintext."""
        key = crypto_service.derive_key(test_password, test_salt)
        ciphertext = crypto_service.encrypt(test_plaintext, key)
        assert ciphertext != test_plaintext

    def test_encrypt_includes_nonce(
        self,
        crypto_service: CryptoService,
        test_password: str,
        test_salt: bytes,
        test_plaintext: bytes,
    ) -> None:
        """Ciphertext should be larger than plaintext (includes nonce + tag)."""
        key = crypto_service.derive_key(test_password, test_salt)
        ciphertext = crypto_service.encrypt(test_plaintext, key)
        # 12 bytes nonce + 16 bytes tag = 28 bytes overhead minimum
        assert len(ciphertext) >= len(test_plaintext) + 28

    def test_encrypt_produces_different_ciphertext_each_time(
        self,
        crypto_service: CryptoService,
        test_password: str,
        test_salt: bytes,
        test_plaintext: bytes,
    ) -> None:
        """Each encryption should produce unique ciphertext (random nonce)."""
        key = crypto_service.derive_key(test_password, test_salt)
        ciphertext1 = crypto_service.encrypt(test_plaintext, key)
        ciphertext2 = crypto_service.encrypt(test_plaintext, key)
        assert ciphertext1 != ciphertext2

    def test_encrypt_empty_data(
        self, crypto_service: CryptoService, test_password: str, test_salt: bytes
    ) -> None:
        """encrypt should handle empty plaintext."""
        key = crypto_service.derive_key(test_password, test_salt)
        ciphertext = crypto_service.encrypt(b"", key)
        # Should still have nonce + tag
        assert len(ciphertext) >= 28


# =============================================================================
# Decryption Tests
# =============================================================================


class TestDecryption:
    """Tests for AES-256-GCM decryption."""

    def test_decrypt_recovers_plaintext(
        self,
        crypto_service: CryptoService,
        test_password: str,
        test_salt: bytes,
        test_plaintext: bytes,
    ) -> None:
        """decrypt should recover original plaintext."""
        key = crypto_service.derive_key(test_password, test_salt)
        ciphertext = crypto_service.encrypt(test_plaintext, key)
        decrypted = crypto_service.decrypt(ciphertext, key)
        assert decrypted == test_plaintext

    def test_decrypt_with_wrong_key_fails(
        self,
        crypto_service: CryptoService,
        test_password: str,
        test_salt: bytes,
        test_plaintext: bytes,
    ) -> None:
        """decrypt should raise EncryptionError with wrong key."""
        key = crypto_service.derive_key(test_password, test_salt)
        ciphertext = crypto_service.encrypt(test_plaintext, key)

        # Use different key
        wrong_key = crypto_service.derive_key("wrong_password", test_salt)
        with pytest.raises(EncryptionError):
            crypto_service.decrypt(ciphertext, wrong_key)

    def test_decrypt_with_tampered_data_fails(
        self,
        crypto_service: CryptoService,
        test_password: str,
        test_salt: bytes,
        test_plaintext: bytes,
    ) -> None:
        """decrypt should detect tampered ciphertext."""
        key = crypto_service.derive_key(test_password, test_salt)
        ciphertext = crypto_service.encrypt(test_plaintext, key)

        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[-1] ^= 0xFF  # Flip bits in last byte
        with pytest.raises(EncryptionError):
            crypto_service.decrypt(bytes(tampered), key)

    def test_decrypt_with_truncated_data_fails(
        self,
        crypto_service: CryptoService,
        test_password: str,
        test_salt: bytes,
        test_plaintext: bytes,
    ) -> None:
        """decrypt should fail on truncated ciphertext."""
        key = crypto_service.derive_key(test_password, test_salt)
        ciphertext = crypto_service.encrypt(test_plaintext, key)

        # Truncate ciphertext
        with pytest.raises(EncryptionError):
            crypto_service.decrypt(ciphertext[:-10], key)

    def test_decrypt_empty_ciphertext_fails(
        self, crypto_service: CryptoService, test_password: str, test_salt: bytes
    ) -> None:
        """decrypt should fail on empty ciphertext."""
        key = crypto_service.derive_key(test_password, test_salt)
        with pytest.raises(EncryptionError):
            crypto_service.decrypt(b"", key)


# =============================================================================
# Roundtrip Tests
# =============================================================================


class TestEncryptionRoundtrip:
    """End-to-end encryption/decryption roundtrip tests."""

    def test_roundtrip_various_data_sizes(
        self, crypto_service: CryptoService, test_password: str, test_salt: bytes
    ) -> None:
        """Roundtrip should work for various data sizes."""
        key = crypto_service.derive_key(test_password, test_salt)

        test_sizes = [1, 16, 100, 1000, 10000, 100000]
        for size in test_sizes:
            plaintext = os.urandom(size)
            ciphertext = crypto_service.encrypt(plaintext, key)
            decrypted = crypto_service.decrypt(ciphertext, key)
            assert decrypted == plaintext, f"Failed for size {size}"

    def test_roundtrip_unicode_content(
        self, crypto_service: CryptoService, test_password: str, test_salt: bytes
    ) -> None:
        """Roundtrip should handle UTF-8 encoded content."""
        key = crypto_service.derive_key(test_password, test_salt)
        plaintext = "Hello, 世界! 🔐".encode("utf-8")
        ciphertext = crypto_service.encrypt(plaintext, key)
        decrypted = crypto_service.decrypt(ciphertext, key)
        assert decrypted == plaintext

    def test_roundtrip_binary_content(
        self, crypto_service: CryptoService, test_password: str, test_salt: bytes
    ) -> None:
        """Roundtrip should handle arbitrary binary content."""
        key = crypto_service.derive_key(test_password, test_salt)
        # Include null bytes and all byte values
        plaintext = bytes(range(256))
        ciphertext = crypto_service.encrypt(plaintext, key)
        decrypted = crypto_service.decrypt(ciphertext, key)
        assert decrypted == plaintext


# =============================================================================
# Verification Hash Tests
# =============================================================================


class TestVerificationHash:
    """Tests for password verification hash."""

    def test_create_verification_hash_returns_32_bytes(
        self, crypto_service: CryptoService, test_password: str, test_salt: bytes
    ) -> None:
        """create_verification_hash should return 32 bytes."""
        key = crypto_service.derive_key(test_password, test_salt)
        hash_value = crypto_service.create_verification_hash(key)
        assert len(hash_value) == 32

    def test_verification_hash_is_deterministic(
        self, crypto_service: CryptoService, test_password: str, test_salt: bytes
    ) -> None:
        """Same key should produce same verification hash."""
        key = crypto_service.derive_key(test_password, test_salt)
        hash1 = crypto_service.create_verification_hash(key)
        hash2 = crypto_service.create_verification_hash(key)
        assert hash1 == hash2

    def test_verify_password_correct(
        self, crypto_service: CryptoService, test_password: str
    ) -> None:
        """verify_password should return True for correct password."""
        salt = crypto_service.generate_salt()
        key = crypto_service.derive_key(test_password, salt)
        verification_hash = crypto_service.create_verification_hash(key)

        result = crypto_service.verify_password(test_password, salt, verification_hash)
        assert result is True

    def test_verify_password_incorrect(
        self, crypto_service: CryptoService, test_password: str
    ) -> None:
        """verify_password should return False for wrong password."""
        salt = crypto_service.generate_salt()
        key = crypto_service.derive_key(test_password, salt)
        verification_hash = crypto_service.create_verification_hash(key)

        result = crypto_service.verify_password("wrong_password", salt, verification_hash)
        assert result is False
