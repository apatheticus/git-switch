"""GPG keyring service for Git-Switch.

This module provides functionality for managing GPG keys using the
python-gnupg library.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
from pathlib import Path

from src.models.exceptions import GPGServiceError

logger = logging.getLogger(__name__)


class GPGService:
    """GPG keyring operations using python-gnupg.

    This service handles:
    - Checking if GPG is installed
    - Listing keys in keyring
    - Importing/exporting keys
    - Deleting keys
    - Verifying signing capability
    - Key validation
    """

    def __init__(self, gnupghome: Path | None = None) -> None:
        """Initialize the GPG service.

        Args:
            gnupghome: Optional custom GPG home directory.
        """
        self._gnupghome = gnupghome
        self._gpg = None
        self._initialize_gpg()

    def _initialize_gpg(self) -> None:
        """Initialize the python-gnupg interface."""
        try:
            import gnupg

            gpg_path = shutil.which("gpg")
            if gpg_path:
                self._gpg = gnupg.GPG(
                    gpgbinary=gpg_path,
                    gnupghome=str(self._gnupghome) if self._gnupghome else None,
                )
            else:
                logger.debug("GPG binary not found in PATH")
                self._gpg = None
        except ImportError:
            logger.warning("python-gnupg not installed")
            self._gpg = None
        except Exception as e:
            logger.warning(f"Failed to initialize GPG: {e}")
            self._gpg = None

    def is_gpg_installed(self) -> bool:
        """Check if GnuPG is available.

        Returns:
            True if gpg command is available, False otherwise.
        """
        return shutil.which("gpg") is not None

    def list_keys(self) -> list[dict[str, str]]:
        """List keys in the GPG keyring.

        Returns:
            List of dicts with: keyid, fingerprint, uids.

        Raises:
            GPGServiceError: If gpg command fails.
        """
        if self._gpg is None:
            raise GPGServiceError("GPG not available")

        try:
            keys = self._gpg.list_keys(True)  # True for secret keys
            return [
                {
                    "keyid": key.get("keyid", ""),
                    "fingerprint": key.get("fingerprint", ""),
                    "uids": key.get("uids", []),
                }
                for key in keys
            ]
        except Exception as e:
            raise GPGServiceError(f"Failed to list keys: {e}") from e

    def import_key(self, private_key: bytes) -> str | None:
        """Import a GPG private key into the keyring.

        Args:
            private_key: Armored or binary GPG private key.

        Returns:
            Key ID of imported key, or None on failure.

        Raises:
            GPGServiceError: If import fails.
        """
        if self._gpg is None:
            raise GPGServiceError("GPG not available")

        try:
            # Decode if bytes
            if isinstance(private_key, bytes):
                key_data = private_key.decode("utf-8", errors="replace")
            else:
                key_data = private_key

            result = self._gpg.import_keys(key_data)

            if result.ok and result.fingerprints:
                # Return the last 16 characters as key ID
                fingerprint = result.fingerprints[0]
                return fingerprint[-16:]

            logger.warning(f"GPG import failed: {result.stderr}")
            return None

        except GPGServiceError:
            raise
        except Exception as e:
            raise GPGServiceError(f"Failed to import key: {e}") from e

    def export_key(self, key_id: str, armor: bool = True) -> bytes | None:
        """Export a GPG key from the keyring.

        Args:
            key_id: GPG key ID to export.
            armor: Whether to use ASCII armor (default: True).

        Returns:
            Exported key bytes, or None if key not found.

        Raises:
            GPGServiceError: If export fails.
        """
        if self._gpg is None:
            raise GPGServiceError("GPG not available")

        try:
            result = self._gpg.export_keys(key_id, secret=True, armor=armor)

            if not result:
                return None

            if isinstance(result, str):
                return result.encode("utf-8")
            return result

        except Exception as e:
            raise GPGServiceError(f"Failed to export key: {e}") from e

    def delete_key(self, key_id: str) -> bool:
        """Delete a key from the GPG keyring.

        Args:
            key_id: GPG key ID to delete.

        Returns:
            True if deleted successfully, False otherwise.

        Raises:
            GPGServiceError: If delete fails.
        """
        if self._gpg is None:
            raise GPGServiceError("GPG not available")

        try:
            # First delete secret key, then public key
            result = self._gpg.delete_keys(key_id, secret=True)
            if not result.ok:
                return False

            result = self._gpg.delete_keys(key_id)
            return result.ok

        except Exception as e:
            raise GPGServiceError(f"Failed to delete key: {e}") from e

    def verify_signing_capability(self, key_id: str) -> bool:
        """Verify that a key can be used for signing.

        Args:
            key_id: GPG key ID to verify.

        Returns:
            True if key can sign, False otherwise.
        """
        if self._gpg is None:
            return False

        try:
            keys = self._gpg.list_keys(True, keys=key_id)

            for key in keys:
                # Check if key has signing capability
                # GPG key capabilities: e=encrypt, s=sign, c=certify, a=authenticate
                cap = key.get("cap", "")
                if "s" in cap.lower():
                    return True

                # Also check subkeys
                for subkey in key.get("subkeys", []):
                    if len(subkey) > 1 and "s" in str(subkey[1]).lower():
                        return True

            return False

        except Exception as e:
            logger.warning(f"Failed to verify signing capability: {e}")
            return False

    def validate_key(self, private_key: bytes) -> tuple[bool, str, str]:
        """Validate GPG key format and extract key ID.

        Args:
            private_key: GPG private key bytes.

        Returns:
            Tuple of (valid: bool, key_id: str, error_message: str).
        """
        if self._gpg is None:
            return False, "", "GPG not available"

        try:
            # Create a temporary directory for key scanning
            with tempfile.TemporaryDirectory() as tmpdir:
                # Write key to temp file
                key_file = Path(tmpdir) / "temp.key"
                key_file.write_bytes(private_key)

                # Try to scan the key
                import gnupg

                tmp_gpg = gnupg.GPG(gnupghome=tmpdir)

                # Decode if bytes
                if isinstance(private_key, bytes):
                    key_data = private_key.decode("utf-8", errors="replace")
                else:
                    key_data = private_key

                result = tmp_gpg.import_keys(key_data)

                if result.ok and result.fingerprints:
                    fingerprint = result.fingerprints[0]
                    key_id = fingerprint[-16:]
                    return True, key_id, ""
                else:
                    return False, "", "Invalid key format or corrupted key"

        except Exception as e:
            return False, "", str(e)


__all__ = ["GPGService"]
