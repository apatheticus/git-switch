"""Credential validation service for Git-Switch.

This module provides functionality for validating SSH and GPG credentials
before they are saved or used for Git operations.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.services.protocols import GPGServiceProtocol, SSHServiceProtocol

logger = logging.getLogger(__name__)


class ValidationService:
    """Service for validating SSH and GPG credentials.

    This service provides methods to:
    - Validate SSH private key format and passphrase
    - Test SSH connections to remote hosts
    - Validate GPG key format and extract key ID
    - Verify GPG signing capability
    """

    def __init__(
        self,
        ssh_service: SSHServiceProtocol | None = None,
        gpg_service: GPGServiceProtocol | None = None,
    ) -> None:
        """Initialize the validation service.

        Args:
            ssh_service: Service for SSH operations (optional).
            gpg_service: Service for GPG operations (optional).
        """
        self._ssh_service = ssh_service
        self._gpg_service = gpg_service

    def validate_ssh_key(
        self,
        private_key: bytes,
        public_key: bytes,  # noqa: ARG002
        passphrase: str | None = None,
    ) -> tuple[bool, str]:
        """Validate SSH private key format and passphrase.

        Args:
            private_key: SSH private key bytes.
            public_key: SSH public key bytes (reserved for future use).
            passphrase: Passphrase if key is encrypted.

        Returns:
            Tuple of (valid: bool, message: str).
            Message describes the validation result or error.
        """
        if self._ssh_service is None:
            return False, "SSH service not available"

        try:
            valid, error = self._ssh_service.validate_private_key(
                private_key, passphrase
            )
        except Exception as e:
            logger.warning(f"SSH key validation error: {e}")
            return False, f"SSH validation error: {e}"
        else:
            if valid:
                return True, "Valid SSH key"
            return False, error or "Invalid key format"

    def validate_ssh_connection(
        self, host: str = "github.com"
    ) -> tuple[bool, str]:
        """Test SSH connection to a host.

        Args:
            host: Host to test connection to (default: github.com).

        Returns:
            Tuple of (success: bool, message: str).
            Message contains username on success or error details on failure.
        """
        if self._ssh_service is None:
            return False, "SSH service not available"

        try:
            success, message = self._ssh_service.test_connection(host)
        except Exception as e:
            logger.warning(f"SSH connection test error: {e}")
            return False, f"Connection error: {e}"
        else:
            return success, message

    def validate_gpg_key(
        self, private_key: bytes
    ) -> tuple[bool, str, str]:
        """Validate GPG key format and extract key ID.

        Args:
            private_key: GPG private key bytes.

        Returns:
            Tuple of (valid: bool, key_id: str, message: str).
            key_id is the extracted GPG key ID, empty on failure.
            message describes the result or error.
        """
        if self._gpg_service is None:
            return False, "", "GPG service not available"

        try:
            valid, key_id, error = self._gpg_service.validate_key(private_key)
        except Exception as e:
            logger.warning(f"GPG key validation error: {e}")
            return False, "", f"GPG validation error: {e}"
        else:
            if valid:
                return True, key_id, ""
            return False, "", error or "Invalid GPG key format"

    def validate_gpg_signing(self, key_id: str) -> tuple[bool, str]:
        """Verify that a GPG key can be used for signing.

        Args:
            key_id: GPG key ID to verify.

        Returns:
            Tuple of (valid: bool, message: str).
            Message describes signing capability or error.
        """
        if self._gpg_service is None:
            return False, "GPG service not available"

        try:
            can_sign = self._gpg_service.verify_signing_capability(key_id)
        except Exception as e:
            logger.warning(f"GPG signing verification error: {e}")
            return False, f"GPG signing verification error: {e}"
        else:
            if can_sign:
                return True, "Key can sign"
            return False, "Key does not have signing capability"

    def validate_all(  # noqa: PLR0913
        self,
        ssh_private_key: bytes,
        ssh_public_key: bytes,
        ssh_passphrase: str | None = None,
        test_ssh_connection: bool = True,
        gpg_private_key: bytes | None = None,
        test_gpg_signing: bool = False,
        ssh_host: str = "github.com",
    ) -> dict[str, tuple[bool | None, str]]:
        """Validate all credentials based on provided flags.

        Args:
            ssh_private_key: SSH private key bytes.
            ssh_public_key: SSH public key bytes.
            ssh_passphrase: SSH passphrase if key is encrypted.
            test_ssh_connection: Whether to test SSH connection.
            gpg_private_key: GPG private key bytes (optional).
            test_gpg_signing: Whether to verify GPG signing capability.
            ssh_host: Host to test SSH connection to.

        Returns:
            Dictionary with validation results:
            - "ssh_format": (bool, message) - SSH key format validation
            - "ssh_connection": (bool | None, message) - SSH connection test
            - "gpg_format": (bool | None, message) - GPG key format validation
            - "gpg_signing": (bool | None, message) - GPG signing capability
        """
        results: dict[str, tuple[bool | None, str]] = {}

        # Always validate SSH key format
        ssh_valid, ssh_message = self.validate_ssh_key(
            ssh_private_key, ssh_public_key, ssh_passphrase
        )
        results["ssh_format"] = (ssh_valid, ssh_message)

        # Optionally test SSH connection
        if test_ssh_connection:
            conn_valid, conn_message = self.validate_ssh_connection(ssh_host)
            results["ssh_connection"] = (conn_valid, conn_message)
        else:
            results["ssh_connection"] = (None, "Skipped")

        # Validate GPG key if provided
        gpg_key_id = ""
        if gpg_private_key is not None:
            gpg_valid, gpg_key_id, gpg_message = self.validate_gpg_key(gpg_private_key)
            gpg_msg = gpg_message if gpg_message else f"Valid key: {gpg_key_id}"
            results["gpg_format"] = (gpg_valid, gpg_msg)
        else:
            results["gpg_format"] = (None, "Skipped - no GPG key provided")

        # Optionally test GPG signing capability
        if test_gpg_signing and gpg_private_key is not None and gpg_key_id:
            sign_valid, sign_message = self.validate_gpg_signing(gpg_key_id)
            results["gpg_signing"] = (sign_valid, sign_message)
        else:
            results["gpg_signing"] = (None, "Skipped")

        return results


__all__ = ["ValidationService"]
