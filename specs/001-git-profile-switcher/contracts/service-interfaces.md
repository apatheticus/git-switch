# Service Interfaces: Git-Switch Profile Manager

**Branch**: `001-git-profile-switcher` | **Date**: 2026-01-17

## Overview

This document defines the internal service contracts (Protocol classes) for the Git-Switch application. These interfaces ensure loose coupling between layers and enable unit testing via dependency injection.

---

## Architecture Layers

```
┌──────────────────────────────────────────────────────────┐
│                      UI Layer                            │
│  (DearPyGui views, dialogs, system tray)                │
│  May ONLY call: Core Layer                              │
└──────────────────────────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────┐
│                     Core Layer                           │
│  (ProfileManager, SessionManager, Crypto)               │
│  May ONLY call: Services Layer, Models                  │
└──────────────────────────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────┐
│                   Services Layer                         │
│  (GitService, SSHService, GPGService, CredentialService)│
│  May ONLY call: Models, External Libraries              │
└──────────────────────────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────┐
│                    Models Layer                          │
│  (Profile, Repository, Settings, Exceptions)            │
│  No dependencies on other layers                        │
└──────────────────────────────────────────────────────────┘
```

---

## Service Layer Protocols

### 1. GitServiceProtocol

Manages Git configuration (global and local).

```python
from typing import Protocol, Optional
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
        signing_key: Optional[str] = None,
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
        signing_key: Optional[str] = None,
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
```

---

### 2. SSHServiceProtocol

Manages Windows OpenSSH ssh-agent operations.

```python
from typing import Protocol, Optional
from pathlib import Path

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
        passphrase: Optional[str] = None,
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
        passphrase: Optional[str] = None,
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
```

---

### 3. GPGServiceProtocol

Manages GPG keyring operations.

```python
from typing import Protocol, Optional

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

    def import_key(self, private_key: bytes) -> Optional[str]:
        """Import a GPG private key into the keyring.

        Args:
            private_key: Armored or binary GPG private key.

        Returns:
            Key ID of imported key, or None on failure.

        Raises:
            GPGServiceError: If import fails.
        """
        ...

    def export_key(self, key_id: str, armor: bool = True) -> Optional[bytes]:
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
```

---

### 4. CredentialServiceProtocol

Manages Windows Credential Manager operations.

```python
from typing import Protocol

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
```

---

## Core Layer Protocols

### 5. CryptoServiceProtocol

Handles all encryption/decryption operations.

```python
from typing import Protocol
from pathlib import Path

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
```

---

### 6. SessionManagerProtocol

Manages application session and auto-lock.

```python
from typing import Protocol, Optional, Callable
from datetime import datetime

class SessionManagerProtocol(Protocol):
    """Protocol for session management and auto-lock."""

    @property
    def is_unlocked(self) -> bool:
        """Whether the session is currently unlocked."""
        ...

    @property
    def encryption_key(self) -> Optional[bytes]:
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
```

---

### 7. ProfileManagerProtocol

Manages profile CRUD and switching operations.

```python
from typing import Protocol, Optional
from uuid import UUID
from pathlib import Path

# Forward reference to models
from models.profile import Profile

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

    def get_profile(self, profile_id: UUID) -> Optional[Profile]:
        """Get a specific profile by ID.

        Args:
            profile_id: Profile UUID.

        Returns:
            Profile if found, None otherwise.

        Raises:
            SessionExpiredError: If session is locked.
        """
        ...

    def get_active_profile(self) -> Optional[Profile]:
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
        ssh_passphrase: Optional[str] = None,
        organization: Optional[str] = None,
        gpg_enabled: bool = False,
        gpg_key_id: Optional[str] = None,
        gpg_private_key: Optional[bytes] = None,
        gpg_public_key: Optional[bytes] = None,
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
        **kwargs,
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
        scope: str = "global",  # "global" or "local"
        repo_path: Optional[Path] = None,  # Required if scope="local"
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
        ssh_passphrase: Optional[str] = None,
        test_ssh_connection: bool = True,
        gpg_private_key: Optional[bytes] = None,
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
```

---

### 8. RepositoryManagerProtocol

Manages repository registration and local config.

```python
from typing import Protocol, Optional
from uuid import UUID
from pathlib import Path

from models.repository import Repository

class RepositoryManagerProtocol(Protocol):
    """Protocol for repository management operations."""

    def list_repositories(self) -> list[Repository]:
        """Get all registered repositories.

        Returns:
            List of Repository objects.
        """
        ...

    def get_repository(self, repo_id: UUID) -> Optional[Repository]:
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
        assigned_profile_id: Optional[UUID] = None,
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
        profile_id: Optional[UUID],
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
        scope: str = "local",  # "local" or "global"
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
```

---

## Dependency Injection Container

```python
from dataclasses import dataclass
from typing import Optional

@dataclass
class ServiceContainer:
    """Dependency injection container for all services."""

    # Services layer
    git_service: GitServiceProtocol
    ssh_service: SSHServiceProtocol
    gpg_service: GPGServiceProtocol
    credential_service: CredentialServiceProtocol

    # Core layer
    crypto_service: CryptoServiceProtocol
    session_manager: SessionManagerProtocol
    profile_manager: ProfileManagerProtocol
    repository_manager: RepositoryManagerProtocol


def create_container() -> ServiceContainer:
    """Create production service container with real implementations."""
    # Implementation creates concrete classes and wires dependencies
    ...


def create_test_container(
    git_service: Optional[GitServiceProtocol] = None,
    ssh_service: Optional[SSHServiceProtocol] = None,
    # ... other overrides
) -> ServiceContainer:
    """Create test container with mock implementations."""
    # Implementation creates mock services, uses overrides where provided
    ...
```

---

## Summary

| Protocol | Layer | Primary Responsibility |
|----------|-------|----------------------|
| GitServiceProtocol | Services | Git configuration read/write |
| SSHServiceProtocol | Services | Windows ssh-agent management |
| GPGServiceProtocol | Services | GPG keyring operations |
| CredentialServiceProtocol | Services | Windows Credential Manager |
| CryptoServiceProtocol | Core | AES-256-GCM encryption, PBKDF2 |
| SessionManagerProtocol | Core | Master password, auto-lock |
| ProfileManagerProtocol | Core | Profile CRUD, switching |
| RepositoryManagerProtocol | Core | Repository registration |

All services follow the constitution's dependency injection mandate and can be easily mocked for testing.
