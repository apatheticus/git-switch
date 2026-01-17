"""Core layer Protocol classes for Git-Switch.

This module defines the interfaces for core application logic
(Crypto, Session, Profile, Repository management).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path
    from uuid import UUID

    from src.models.profile import Profile
    from src.models.repository import Repository


class CryptoServiceProtocol(Protocol):
    """Protocol for encryption/decryption operations."""

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2.

        Args:
            password: Master password.
            salt: 32-byte random salt.

        Returns:
            32-byte derived key (AES-256).
        """
        ...

    def encrypt(self, plaintext: bytes, key: bytes) -> bytes:
        """Encrypt data using AES-256-GCM.

        Args:
            plaintext: Data to encrypt.
            key: 32-byte encryption key.

        Returns:
            Encrypted data with prepended nonce.

        Raises:
            EncryptionError: If encryption fails.
        """
        ...

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        """Decrypt data using AES-256-GCM.

        Args:
            ciphertext: Encrypted data with prepended nonce.
            key: 32-byte encryption key.

        Returns:
            Decrypted plaintext.

        Raises:
            EncryptionError: If decryption fails (wrong key or tampered data).
        """
        ...

    def generate_salt(self) -> bytes:
        """Generate a cryptographically secure random salt.

        Returns:
            32-byte random salt.
        """
        ...

    def create_verification_hash(self, key: bytes) -> bytes:
        """Create verification hash for password validation.

        Args:
            key: Derived encryption key.

        Returns:
            32-byte HMAC-SHA256 of known constant.
        """
        ...

    def verify_password(
        self,
        password: str,
        salt: bytes,
        verification_hash: bytes,
    ) -> bool:
        """Verify master password against stored hash.

        Args:
            password: Password to verify.
            salt: Installation salt.
            verification_hash: Stored verification hash.

        Returns:
            True if password is correct, False otherwise.
        """
        ...

    def secure_delete_file(self, path: Path) -> None:
        """Securely delete a file by overwriting before removal.

        Args:
            path: Path to file to delete.
        """
        ...


class SessionManagerProtocol(Protocol):
    """Protocol for session management and auto-lock."""

    @property
    def is_unlocked(self) -> bool:
        """Whether the session is currently unlocked."""
        ...

    @property
    def encryption_key(self) -> bytes | None:
        """Current session encryption key (None if locked)."""
        ...

    def unlock(self, password: str) -> bool:
        """Unlock the session with master password.

        Args:
            password: Master password.

        Returns:
            True if unlocked successfully, False if wrong password.

        Raises:
            AuthenticationError: If password verification fails.
        """
        ...

    def lock(self) -> None:
        """Lock the session and clear encryption key from memory."""
        ...

    def setup_master_password(self, password: str) -> None:
        """Set up master password for first-time use.

        Args:
            password: New master password.

        Raises:
            AuthenticationError: If setup fails.
        """
        ...

    def change_master_password(
        self,
        current_password: str,
        new_password: str,
    ) -> None:
        """Change the master password.

        Args:
            current_password: Current master password.
            new_password: New master password.

        Raises:
            InvalidPasswordError: If current password is wrong.
            AuthenticationError: If change fails.
        """
        ...

    def reset_idle_timer(self) -> None:
        """Reset the idle timer (call on user activity)."""
        ...

    def set_lock_callback(self, callback: Callable[[], None]) -> None:
        """Set callback to invoke when auto-lock triggers.

        Args:
            callback: Function to call when session auto-locks.
        """
        ...

    def has_master_password(self) -> bool:
        """Check if master password has been set up.

        Returns:
            True if master password exists, False for first-time setup.
        """
        ...


class ProfileManagerProtocol(Protocol):
    """Protocol for profile management operations."""

    def list_profiles(self) -> list[Profile]:
        """Get all profiles.

        Returns:
            List of Profile objects.

        Raises:
            SessionExpiredError: If session is locked.
        """
        ...

    def get_profile(self, profile_id: UUID) -> Profile | None:
        """Get a specific profile by ID.

        Args:
            profile_id: Profile UUID.

        Returns:
            Profile if found, None otherwise.

        Raises:
            SessionExpiredError: If session is locked.
        """
        ...

    def get_active_profile(self) -> Profile | None:
        """Get the currently active profile.

        Returns:
            Active Profile if one is set, None otherwise.

        Raises:
            SessionExpiredError: If session is locked.
        """
        ...

    def create_profile(
        self,
        name: str,
        git_username: str,
        git_email: str,
        ssh_private_key: bytes,
        ssh_public_key: bytes,
        ssh_passphrase: str | None = None,
        organization: str | None = None,
        gpg_enabled: bool = False,
        gpg_key_id: str | None = None,
        gpg_private_key: bytes | None = None,
        gpg_public_key: bytes | None = None,
    ) -> Profile:
        """Create a new profile.

        Args:
            name: Profile display name.
            git_username: Git user.name value.
            git_email: Git user.email value.
            ssh_private_key: SSH private key bytes.
            ssh_public_key: SSH public key bytes.
            ssh_passphrase: SSH key passphrase (if protected).
            organization: Optional organization name.
            gpg_enabled: Whether to enable GPG signing.
            gpg_key_id: GPG key ID (required if gpg_enabled).
            gpg_private_key: GPG private key (required if gpg_enabled).
            gpg_public_key: GPG public key.

        Returns:
            Created Profile object.

        Raises:
            ProfileValidationError: If validation fails.
            SessionExpiredError: If session is locked.
        """
        ...

    def update_profile(
        self,
        profile_id: UUID,
        **kwargs: object,
    ) -> Profile:
        """Update an existing profile.

        Args:
            profile_id: Profile UUID.
            **kwargs: Fields to update (same as create_profile).

        Returns:
            Updated Profile object.

        Raises:
            ProfileNotFoundError: If profile doesn't exist.
            ProfileValidationError: If validation fails.
            SessionExpiredError: If session is locked.
        """
        ...

    def delete_profile(self, profile_id: UUID) -> None:
        """Delete a profile.

        Args:
            profile_id: Profile UUID.

        Raises:
            ProfileNotFoundError: If profile doesn't exist.
            SessionExpiredError: If session is locked.
        """
        ...

    def switch_profile(
        self,
        profile_id: UUID,
        scope: str = "global",
        repo_path: Path | None = None,
    ) -> None:
        """Switch to a profile (apply configuration).

        Args:
            profile_id: Profile UUID to switch to.
            scope: "global" for global config, "local" for repository config.
            repo_path: Repository path (required for local scope).

        Raises:
            ProfileNotFoundError: If profile doesn't exist.
            InvalidRepositoryError: If repo_path is invalid (local scope).
            GitServiceError: If Git config update fails.
            SSHServiceError: If SSH agent update fails.
            SessionExpiredError: If session is locked.
        """
        ...

    def validate_credentials(
        self,
        ssh_private_key: bytes,
        ssh_public_key: bytes,
        ssh_passphrase: str | None = None,
        test_ssh_connection: bool = True,
        gpg_private_key: bytes | None = None,
        test_gpg_signing: bool = False,
    ) -> dict[str, tuple[bool, str]]:
        """Validate profile credentials before saving.

        Args:
            ssh_private_key: SSH private key bytes.
            ssh_public_key: SSH public key bytes.
            ssh_passphrase: SSH key passphrase.
            test_ssh_connection: Whether to test SSH connectivity.
            gpg_private_key: GPG private key bytes.
            test_gpg_signing: Whether to test GPG signing.

        Returns:
            Dictionary with validation results:
            {
                "ssh_format": (valid: bool, message: str),
                "ssh_passphrase": (valid: bool, message: str),
                "ssh_connection": (valid: bool, message: str),
                "gpg_format": (valid: bool, message: str),
                "gpg_signing": (valid: bool, message: str),
            }
        """
        ...


class RepositoryManagerProtocol(Protocol):
    """Protocol for repository management operations."""

    def list_repositories(self) -> list[Repository]:
        """Get all registered repositories.

        Returns:
            List of Repository objects.
        """
        ...

    def get_repository(self, repo_id: UUID) -> Repository | None:
        """Get a specific repository by ID.

        Args:
            repo_id: Repository UUID.

        Returns:
            Repository if found, None otherwise.
        """
        ...

    def add_repository(
        self,
        path: Path,
        assigned_profile_id: UUID | None = None,
    ) -> Repository:
        """Register a new repository.

        Args:
            path: Path to repository root.
            assigned_profile_id: Profile to assign (optional).

        Returns:
            Created Repository object.

        Raises:
            InvalidRepositoryError: If path is not a valid Git repository.
            RepositoryError: If repository is already registered.
        """
        ...

    def remove_repository(self, repo_id: UUID) -> None:
        """Unregister a repository.

        Args:
            repo_id: Repository UUID.

        Raises:
            RepositoryError: If repository not found.
        """
        ...

    def assign_profile(
        self,
        repo_id: UUID,
        profile_id: UUID | None,
    ) -> Repository:
        """Assign a profile to a repository.

        Args:
            repo_id: Repository UUID.
            profile_id: Profile UUID to assign (None to unassign).

        Returns:
            Updated Repository object.

        Raises:
            RepositoryError: If repository not found.
            ProfileNotFoundError: If profile not found.
        """
        ...

    def apply_profile(
        self,
        repo_id: UUID,
        scope: str = "local",
    ) -> None:
        """Apply assigned profile to repository.

        Args:
            repo_id: Repository UUID.
            scope: "local" for local config, "global" for global config.

        Raises:
            RepositoryError: If repository not found or no profile assigned.
            GitServiceError: If config update fails.
        """
        ...

    def validate_repository(self, path: Path) -> bool:
        """Check if path is a valid Git repository.

        Args:
            path: Path to check.

        Returns:
            True if valid Git repository, False otherwise.
        """
        ...


__all__ = [
    "CryptoServiceProtocol",
    "ProfileManagerProtocol",
    "RepositoryManagerProtocol",
    "SessionManagerProtocol",
]
