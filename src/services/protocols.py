"""Service layer Protocol classes for Git-Switch.

This module defines the interfaces for external service interactions
(Git, SSH, GPG, Windows Credential Manager).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from pathlib import Path


class GitServiceProtocol(Protocol):
    """Protocol for Git configuration operations."""

    def is_git_installed(self) -> bool:
        """Check if Git is available in PATH.

        Returns:
            True if git command is available, False otherwise.
        """
        ...

    def get_global_config(self) -> dict[str, str]:
        """Read current Git global configuration.

        Returns:
            Dictionary with keys: user.name, user.email, user.signingkey, commit.gpgsign

        Raises:
            GitServiceError: If git command fails.
        """
        ...

    def set_global_config(
        self,
        username: str,
        email: str,
        signing_key: str | None = None,
        gpg_sign: bool = False,
    ) -> None:
        """Update Git global configuration.

        Args:
            username: Value for user.name
            email: Value for user.email
            signing_key: GPG key ID for user.signingkey (None to unset)
            gpg_sign: Whether to enable commit.gpgsign

        Raises:
            GitServiceError: If git command fails.
        """
        ...

    def set_local_config(
        self,
        repo_path: Path,
        username: str,
        email: str,
        signing_key: str | None = None,
        gpg_sign: bool = False,
    ) -> None:
        """Update Git local configuration for a specific repository.

        Args:
            repo_path: Path to the repository root.
            username: Value for user.name
            email: Value for user.email
            signing_key: GPG key ID for user.signingkey (None to unset)
            gpg_sign: Whether to enable commit.gpgsign

        Raises:
            GitServiceError: If git command fails.
            InvalidRepositoryError: If repo_path is not a valid Git repository.
        """
        ...

    def get_local_config(self, repo_path: Path) -> dict[str, str]:
        """Read Git local configuration for a specific repository.

        Args:
            repo_path: Path to the repository root.

        Returns:
            Dictionary with keys: user.name, user.email, user.signingkey, commit.gpgsign

        Raises:
            GitServiceError: If git command fails.
            InvalidRepositoryError: If repo_path is not a valid Git repository.
        """
        ...


class SSHServiceProtocol(Protocol):
    """Protocol for SSH agent operations (Windows OpenSSH)."""

    def is_agent_running(self) -> bool:
        """Check if Windows ssh-agent service is running.

        Returns:
            True if ssh-agent service is running, False otherwise.
        """
        ...

    def start_agent(self) -> bool:
        """Attempt to start the ssh-agent service.

        Returns:
            True if service started successfully, False otherwise.

        Note:
            May require elevated privileges.
        """
        ...

    def list_keys(self) -> list[str]:
        """List fingerprints of keys currently loaded in ssh-agent.

        Returns:
            List of key fingerprints (SHA256:xxx format).

        Raises:
            SSHServiceError: If ssh-add command fails.
        """
        ...

    def add_key(
        self,
        private_key_path: Path,
        passphrase: str | None = None,
    ) -> bool:
        """Add an SSH private key to the agent.

        Args:
            private_key_path: Path to the private key file.
            passphrase: Key passphrase if the key is protected.

        Returns:
            True if key was added successfully, False otherwise.

        Raises:
            SSHServiceError: If ssh-add command fails.
        """
        ...

    def remove_all_keys(self) -> bool:
        """Remove all keys from the ssh-agent.

        Returns:
            True if keys were removed successfully, False otherwise.

        Raises:
            SSHServiceError: If ssh-add command fails.
        """
        ...

    def test_connection(self, host: str = "github.com") -> tuple[bool, str]:
        """Test SSH connection to a host.

        Args:
            host: Host to test connection to (default: github.com).

        Returns:
            Tuple of (success: bool, message: str).
            Message contains username on success or error details on failure.
        """
        ...

    def get_key_fingerprint(self, public_key: bytes) -> str:
        """Calculate SHA256 fingerprint of a public key.

        Args:
            public_key: SSH public key bytes.

        Returns:
            Fingerprint in SHA256:xxx format.
        """
        ...

    def validate_private_key(
        self,
        private_key: bytes,
        passphrase: str | None = None,
    ) -> tuple[bool, str]:
        """Validate SSH private key format and passphrase.

        Args:
            private_key: Private key bytes.
            passphrase: Passphrase to test if key is encrypted.

        Returns:
            Tuple of (valid: bool, error_message: str).
            error_message is empty on success.
        """
        ...


class GPGServiceProtocol(Protocol):
    """Protocol for GPG keyring operations."""

    def is_gpg_installed(self) -> bool:
        """Check if GnuPG is available.

        Returns:
            True if gpg command is available, False otherwise.
        """
        ...

    def list_keys(self) -> list[dict[str, str]]:
        """List keys in the GPG keyring.

        Returns:
            List of dicts with: keyid, fingerprint, uids.

        Raises:
            GPGServiceError: If gpg command fails.
        """
        ...

    def import_key(self, private_key: bytes) -> str | None:
        """Import a GPG private key into the keyring.

        Args:
            private_key: Armored or binary GPG private key.

        Returns:
            Key ID of imported key, or None on failure.

        Raises:
            GPGServiceError: If import fails.
        """
        ...

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
        ...

    def delete_key(self, key_id: str) -> bool:
        """Delete a key from the GPG keyring.

        Args:
            key_id: GPG key ID to delete.

        Returns:
            True if deleted successfully, False otherwise.

        Raises:
            GPGServiceError: If delete fails.
        """
        ...

    def verify_signing_capability(self, key_id: str) -> bool:
        """Verify that a key can be used for signing.

        Args:
            key_id: GPG key ID to verify.

        Returns:
            True if key can sign, False otherwise.
        """
        ...

    def validate_key(self, private_key: bytes) -> tuple[bool, str, str]:
        """Validate GPG key format and extract key ID.

        Args:
            private_key: GPG private key bytes.

        Returns:
            Tuple of (valid: bool, key_id: str, error_message: str).
        """
        ...


class CredentialServiceProtocol(Protocol):
    """Protocol for Windows Credential Manager operations."""

    def list_git_credentials(self) -> list[str]:
        """List Git-related credential targets.

        Returns:
            List of credential target names (e.g., "git:https://github.com").
        """
        ...

    def delete_credential(self, target: str) -> bool:
        """Delete a specific credential.

        Args:
            target: Credential target name.

        Returns:
            True if deleted successfully, False if not found.

        Raises:
            CredentialServiceError: If deletion fails.
        """
        ...

    def clear_git_credentials(self) -> list[str]:
        """Clear all Git/GitHub cached credentials.

        Returns:
            List of credential targets that were cleared.

        Raises:
            CredentialServiceError: If clearing fails.
        """
        ...

    def has_credential(self, target: str) -> bool:
        """Check if a credential exists.

        Args:
            target: Credential target name.

        Returns:
            True if credential exists, False otherwise.
        """
        ...


__all__ = [
    "CredentialServiceProtocol",
    "GPGServiceProtocol",
    "GitServiceProtocol",
    "SSHServiceProtocol",
]
