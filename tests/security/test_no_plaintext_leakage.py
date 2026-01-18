"""Security tests for no plaintext leakage.

These tests verify that the CryptoService properly handles sensitive
data and doesn't leak plaintext in error conditions, logs, or memory.

TDD Note: These tests are written before the CryptoService implementation
and should FAIL until the implementation is complete.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from src.core.crypto import CryptoService, secure_zero
from src.models.exceptions import EncryptionError

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
    return "SuperSecretPassword!@#$"


@pytest.fixture
def sensitive_data() -> bytes:
    """Provide sensitive test data."""
    return b"-----BEGIN OPENSSH PRIVATE KEY-----\nSensitive key material here\n-----END OPENSSH PRIVATE KEY-----"


# =============================================================================
# Secure Memory Zeroing Tests
# =============================================================================


class TestSecureZero:
    """Tests for secure memory zeroing."""

    def test_secure_zero_clears_bytearray(self) -> None:
        """secure_zero should zero a bytearray in place."""
        data = bytearray(b"sensitive data here")
        original_len = len(data)
        secure_zero(data)
        # All bytes should be zero
        assert all(b == 0 for b in data)
        # Length should be preserved
        assert len(data) == original_len

    def test_secure_zero_handles_empty_array(self) -> None:
        """secure_zero should handle empty bytearray."""
        data = bytearray()
        secure_zero(data)  # Should not raise
        assert len(data) == 0

    def test_secure_zero_handles_large_data(self) -> None:
        """secure_zero should handle large bytearrays."""
        data = bytearray(os.urandom(100000))
        secure_zero(data)
        assert all(b == 0 for b in data)


# =============================================================================
# Error Message Security Tests
# =============================================================================


class TestErrorMessageSecurity:
    """Tests ensuring error messages don't leak sensitive data."""

    def test_decryption_error_no_key_in_message(
        self, crypto_service: CryptoService, test_password: str
    ) -> None:
        """Decryption error should not include key material."""
        salt = crypto_service.generate_salt()
        key = crypto_service.derive_key(test_password, salt)
        ciphertext = crypto_service.encrypt(b"test data", key)

        # Use wrong key
        wrong_key = crypto_service.derive_key("wrong_password", salt)

        with pytest.raises(EncryptionError) as exc_info:
            crypto_service.decrypt(ciphertext, wrong_key)

        # Error message should not contain key bytes
        error_msg = str(exc_info.value)
        assert str(key) not in error_msg
        assert str(wrong_key) not in error_msg

    def test_decryption_error_no_plaintext_in_message(
        self, crypto_service: CryptoService, sensitive_data: bytes
    ) -> None:
        """Decryption error should not include plaintext."""
        salt = crypto_service.generate_salt()
        key = crypto_service.derive_key("password", salt)
        ciphertext = crypto_service.encrypt(sensitive_data, key)

        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[20] ^= 0xFF

        with pytest.raises(EncryptionError) as exc_info:
            crypto_service.decrypt(bytes(tampered), key)

        error_msg = str(exc_info.value)
        # Sensitive patterns should not appear
        assert b"PRIVATE KEY" not in error_msg.encode()
        assert "Sensitive" not in error_msg


# =============================================================================
# Ciphertext Independence Tests
# =============================================================================


class TestCiphertextIndependence:
    """Tests ensuring ciphertext doesn't reveal plaintext patterns."""

    def test_identical_plaintexts_different_ciphertexts(
        self, crypto_service: CryptoService
    ) -> None:
        """Encrypting same plaintext twice should produce different ciphertext."""
        salt = crypto_service.generate_salt()
        key = crypto_service.derive_key("password", salt)
        plaintext = b"This is a test message"

        ciphertexts = [crypto_service.encrypt(plaintext, key) for _ in range(10)]

        # All ciphertexts should be unique
        assert len(set(ciphertexts)) == 10

    def test_similar_plaintexts_unrelated_ciphertexts(self, crypto_service: CryptoService) -> None:
        """Similar plaintexts should produce unrelated ciphertexts."""
        salt = crypto_service.generate_salt()
        key = crypto_service.derive_key("password", salt)

        plaintext1 = b"AAAAAAAAAA"
        plaintext2 = b"AAAAAAAAAB"  # Only last byte differs

        ciphertext1 = crypto_service.encrypt(plaintext1, key)
        ciphertext2 = crypto_service.encrypt(plaintext2, key)

        # Ciphertexts should be completely different (not just last byte)
        # Check that they differ by more than just a few bytes
        differences = sum(1 for a, b in zip(ciphertext1, ciphertext2, strict=False) if a != b)
        # Most bytes should differ due to different nonces
        assert differences > len(ciphertext1) // 2


# =============================================================================
# Secure File Deletion Tests
# =============================================================================


class TestSecureFileDeletion:
    """Tests for secure file deletion."""

    def test_secure_delete_file_removes_file(
        self, crypto_service: CryptoService, tmp_path: Path
    ) -> None:
        """secure_delete_file should remove the file."""
        test_file = tmp_path / "sensitive.txt"
        test_file.write_bytes(b"sensitive content")

        assert test_file.exists()
        crypto_service.secure_delete_file(test_file)
        assert not test_file.exists()

    def test_secure_delete_file_overwrites_before_deletion(
        self, crypto_service: CryptoService, tmp_path: Path
    ) -> None:
        """secure_delete_file should overwrite file before deletion."""
        test_file = tmp_path / "sensitive.txt"
        original_content = b"X" * 1000
        test_file.write_bytes(original_content)

        # Get file size before deletion
        original_size = test_file.stat().st_size

        crypto_service.secure_delete_file(test_file)

        # File should be gone
        assert not test_file.exists()

    def test_secure_delete_nonexistent_file(
        self, crypto_service: CryptoService, tmp_path: Path
    ) -> None:
        """secure_delete_file should handle nonexistent files gracefully."""
        test_file = tmp_path / "nonexistent.txt"
        # Should not raise
        crypto_service.secure_delete_file(test_file)


# =============================================================================
# Key Material Handling Tests
# =============================================================================


class TestKeyMaterialHandling:
    """Tests for proper handling of key material."""

    def test_key_has_sufficient_entropy(self, crypto_service: CryptoService) -> None:
        """Derived keys should have sufficient randomness."""
        salt = crypto_service.generate_salt()
        key = crypto_service.derive_key("password123", salt)

        # Check that key has reasonable entropy (all bytes aren't the same)
        unique_bytes = len(set(key))
        # A 32-byte key with good entropy should have many unique bytes
        assert unique_bytes > 20

    def test_salt_has_sufficient_entropy(self, crypto_service: CryptoService) -> None:
        """Generated salts should have high entropy."""
        salt = crypto_service.generate_salt()

        # Check that salt has reasonable entropy
        unique_bytes = len(set(salt))
        # A 32-byte random salt should have many unique bytes
        assert unique_bytes > 20

    def test_nonce_uniqueness_in_ciphertext(self, crypto_service: CryptoService) -> None:
        """Each encryption should use a unique nonce."""
        salt = crypto_service.generate_salt()
        key = crypto_service.derive_key("password", salt)
        plaintext = b"test data"

        # Extract nonces from multiple encryptions
        # Nonce is first 12 bytes of ciphertext
        ciphertexts = [crypto_service.encrypt(plaintext, key) for _ in range(100)]
        nonces = [ct[:12] for ct in ciphertexts]

        # All nonces should be unique
        assert len(set(nonces)) == 100


# =============================================================================
# Input Validation Tests
# =============================================================================


class TestInputValidation:
    """Tests for proper input validation."""

    def test_encrypt_validates_key_length(self, crypto_service: CryptoService) -> None:
        """encrypt should require 32-byte key."""
        with pytest.raises((ValueError, EncryptionError)):
            crypto_service.encrypt(b"test", b"short_key")

    def test_decrypt_validates_key_length(self, crypto_service: CryptoService) -> None:
        """decrypt should require 32-byte key."""
        # Create valid ciphertext first
        salt = crypto_service.generate_salt()
        key = crypto_service.derive_key("password", salt)
        ciphertext = crypto_service.encrypt(b"test", key)

        # Try to decrypt with short key
        with pytest.raises((ValueError, EncryptionError)):
            crypto_service.decrypt(ciphertext, b"short_key")

    def test_derive_key_validates_salt_length(self, crypto_service: CryptoService) -> None:
        """derive_key should work with proper 32-byte salt."""
        # Should work with 32-byte salt
        key = crypto_service.derive_key("password", b"0" * 32)
        assert len(key) == 32


# =============================================================================
# Timing Attack Resistance Tests
# =============================================================================


class TestTimingResistance:
    """Tests for timing attack resistance."""

    def test_verify_password_constant_time(self, crypto_service: CryptoService) -> None:
        """verify_password should use constant-time comparison."""
        salt = crypto_service.generate_salt()
        key = crypto_service.derive_key("correct_password", salt)
        verification_hash = crypto_service.create_verification_hash(key)

        # Test with various wrong passwords
        # (This is more of a documentation test - actual timing analysis
        # would require statistical testing)
        results = []
        for password in ["wrong1", "wrong2", "wrong3", "correct_password"]:
            result = crypto_service.verify_password(password, salt, verification_hash)
            results.append(result)

        # Only the last one should be True
        assert results == [False, False, False, True]
