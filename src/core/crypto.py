"""Cryptographic service for Git-Switch.

This module provides encryption/decryption operations using AES-256-GCM
and key derivation using PBKDF2-HMAC-SHA256.

Security:
- Uses cryptography library (FIPS-validated primitives)
- AES-256-GCM for authenticated encryption
- PBKDF2 with 100,000 iterations for key derivation
- Secure memory clearing via ctypes
"""

from __future__ import annotations

import contextlib
import ctypes
import hmac
import os
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from src.models.exceptions import EncryptionError

if TYPE_CHECKING:
    from pathlib import Path

# Security constants
SALT_LENGTH = 32  # 256 bits
KEY_LENGTH = 32  # 256 bits for AES-256
NONCE_LENGTH = 12  # 96 bits for GCM
ITERATIONS = 100_000  # PBKDF2 iterations (constitution minimum)
VERIFICATION_CONSTANT = b"GIT-SWITCH-VERIFY"


def secure_zero(data: bytearray) -> None:
    """Securely zero a bytearray in memory.

    Uses ctypes.memset to overwrite memory with zeros, helping
    prevent sensitive data from lingering in memory.

    Args:
        data: Bytearray to zero.

    Note:
        This is a best-effort approach. Python's garbage collector
        may still have references to the original data in memory.
    """
    if len(data) == 0:
        return

    try:
        # Get the address of the bytearray's buffer
        buffer_type = ctypes.c_char * len(data)
        buffer = buffer_type.from_buffer(data)
        ctypes.memset(ctypes.addressof(buffer), 0, len(data))
    except Exception:
        # Fallback: zero manually if ctypes fails
        for i in range(len(data)):
            data[i] = 0


class CryptoService:
    """Service for cryptographic operations.

    Provides AES-256-GCM encryption/decryption and PBKDF2 key derivation.
    Implements CryptoServiceProtocol for dependency injection.

    Attributes:
        iterations: Number of PBKDF2 iterations (default: 100,000).
    """

    def __init__(self, iterations: int = ITERATIONS) -> None:
        """Initialize the crypto service.

        Args:
            iterations: PBKDF2 iteration count (must be >= 100,000).
        """
        if iterations < ITERATIONS:
            raise ValueError(f"Iterations must be at least {ITERATIONS}")
        self._iterations = iterations

    @property
    def iterations(self) -> int:
        """Get the PBKDF2 iteration count."""
        return self._iterations

    def generate_salt(self) -> bytes:
        """Generate a cryptographically secure random salt.

        Returns:
            32-byte random salt.
        """
        return os.urandom(SALT_LENGTH)

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2.

        Uses PBKDF2-HMAC-SHA256 with the configured iteration count.

        Args:
            password: Master password (can be empty but not recommended).
            salt: 32-byte random salt.

        Returns:
            32-byte derived key suitable for AES-256.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=salt,
            iterations=self._iterations,
        )
        return kdf.derive(password.encode("utf-8"))

    def encrypt(self, plaintext: bytes, key: bytes) -> bytes:
        """Encrypt data using AES-256-GCM.

        The output format is: [12-byte nonce][ciphertext][16-byte tag]

        Args:
            plaintext: Data to encrypt.
            key: 32-byte encryption key.

        Returns:
            Encrypted data with prepended nonce and appended auth tag.

        Raises:
            EncryptionError: If encryption fails.
            ValueError: If key length is incorrect.
        """
        if len(key) != KEY_LENGTH:
            raise ValueError(f"Key must be {KEY_LENGTH} bytes")

        try:
            # Generate unique nonce for each encryption
            nonce = os.urandom(NONCE_LENGTH)

            # Create AES-GCM cipher and encrypt
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)

            # Return nonce + ciphertext (ciphertext includes auth tag)
            return nonce + ciphertext

        except Exception as e:
            # Don't leak sensitive info in error message
            raise EncryptionError("Encryption failed") from e

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        """Decrypt data using AES-256-GCM.

        Expects input format: [12-byte nonce][ciphertext][16-byte tag]

        Args:
            ciphertext: Encrypted data with prepended nonce.
            key: 32-byte encryption key.

        Returns:
            Decrypted plaintext.

        Raises:
            EncryptionError: If decryption fails (wrong key or tampered data).
            ValueError: If key length is incorrect.
        """
        if len(key) != KEY_LENGTH:
            raise ValueError(f"Key must be {KEY_LENGTH} bytes")

        # Minimum size: nonce (12) + tag (16) = 28 bytes
        if len(ciphertext) < NONCE_LENGTH + 16:
            raise EncryptionError("Invalid ciphertext: too short")

        try:
            # Extract nonce and actual ciphertext
            nonce = ciphertext[:NONCE_LENGTH]
            encrypted_data = ciphertext[NONCE_LENGTH:]

            # Create AES-GCM cipher and decrypt
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(nonce, encrypted_data, None)

        except Exception as e:
            # Don't leak sensitive info in error message
            raise EncryptionError("Decryption failed: invalid key or corrupted data") from e

    def create_verification_hash(self, key: bytes) -> bytes:
        """Create verification hash for password validation.

        Uses HMAC-SHA256 of a known constant to verify the key
        is correct without storing the key itself.

        Args:
            key: Derived encryption key.

        Returns:
            32-byte HMAC-SHA256 of verification constant.
        """
        return hmac.new(key, VERIFICATION_CONSTANT, "sha256").digest()

    def verify_password(
        self,
        password: str,
        salt: bytes,
        verification_hash: bytes,
    ) -> bool:
        """Verify master password against stored hash.

        Uses constant-time comparison to prevent timing attacks.

        Args:
            password: Password to verify.
            salt: Installation salt.
            verification_hash: Stored verification hash.

        Returns:
            True if password is correct, False otherwise.
        """
        # Derive key from provided password
        key = self.derive_key(password, salt)

        # Create verification hash from derived key
        computed_hash = self.create_verification_hash(key)

        # Constant-time comparison to prevent timing attacks
        return hmac.compare_digest(computed_hash, verification_hash)

    def secure_delete_file(self, path: Path) -> None:
        """Securely delete a file by overwriting before removal.

        Overwrites the file with random data before deletion to make
        recovery more difficult.

        Args:
            path: Path to file to delete.

        Note:
            This is best-effort security. Modern SSDs with wear leveling
            may retain old data in other blocks.
        """
        if not path.exists():
            return

        try:
            # Get file size
            file_size = path.stat().st_size

            # Overwrite with random data
            if file_size > 0:
                with open(path, "r+b") as f:
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())

            # Delete the file
            path.unlink()

        except Exception:
            # If secure deletion fails, still try to delete
            with contextlib.suppress(Exception):
                path.unlink()


__all__ = [
    "ITERATIONS",
    "KEY_LENGTH",
    "NONCE_LENGTH",
    "SALT_LENGTH",
    "CryptoService",
    "secure_zero",
]
