"""Profile data models for Git-Switch.

This module contains dataclasses for Profile, SSHKey, and GPGKey
with validation rules enforced in __post_init__.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID, uuid4


@dataclass
class SSHKey:
    """SSH key pair associated with a profile.

    Attributes:
        private_key_encrypted: AES-256-GCM encrypted private key.
        public_key: Plaintext public key (not sensitive).
        passphrase_encrypted: Encrypted passphrase if key is protected.
        fingerprint: SHA256 fingerprint for display.
    """

    private_key_encrypted: bytes
    public_key: bytes
    passphrase_encrypted: bytes | None = None
    fingerprint: str = ""

    def __post_init__(self) -> None:
        """Validate SSH key fields after initialization."""
        if not self.private_key_encrypted:
            raise ValueError("SSH private key is required")
        if not self.public_key:
            raise ValueError("SSH public key is required")


@dataclass
class GPGKey:
    """GPG signing key configuration.

    Attributes:
        enabled: Whether GPG signing is enabled for this profile.
        key_id: GPG key ID (e.g., "ABCD1234EFGH5678").
        private_key_encrypted: AES-256-GCM encrypted private key.
        public_key: Plaintext public key.
    """

    enabled: bool = False
    key_id: str = ""
    private_key_encrypted: bytes | None = None
    public_key: bytes | None = None

    def __post_init__(self) -> None:
        """Validate GPG key fields after initialization."""
        if self.enabled:
            if not self.key_id:
                raise ValueError("GPG key ID required when GPG is enabled")
            if not self.private_key_encrypted:
                raise ValueError("GPG private key required when GPG is enabled")


@dataclass
class Profile:
    """A Git user profile with associated credentials.

    Attributes:
        id: Unique identifier for the profile.
        name: Display name (e.g., "Acme Corporation").
        git_username: Git config user.name value.
        git_email: Git config user.email value.
        organization: Optional organization/company for display.
        ssh_key: SSH key pair for this profile.
        gpg_key: GPG signing key configuration.
        created_at: Timestamp when the profile was created.
        last_used: Timestamp when the profile was last switched to.
        is_active: Whether this is the currently active profile.
    """

    id: UUID = field(default_factory=uuid4)
    name: str = ""
    git_username: str = ""
    git_email: str = ""
    organization: str = ""
    ssh_key: SSHKey | None = None
    gpg_key: GPGKey = field(default_factory=GPGKey)
    created_at: datetime = field(default_factory=datetime.now)
    last_used: datetime | None = None
    is_active: bool = False

    def __post_init__(self) -> None:
        """Validate profile fields after initialization."""
        self._validate()

    def _validate(self) -> None:
        """Validate profile fields.

        Raises:
            ValueError: If any validation rule is violated.
        """
        if not self.name or not self.name.strip():
            raise ValueError("Profile name is required")
        if not self.git_username or not self.git_username.strip():
            raise ValueError("Git username is required")
        if not self.git_email or not self.git_email.strip():
            raise ValueError("Git email is required")
        if not self._is_valid_email(self.git_email):
            raise ValueError("Invalid email format")

    @property
    def has_ssh_key(self) -> bool:
        """Return True if profile has SSH key configured."""
        return self.ssh_key is not None

    @staticmethod
    def _is_valid_email(email: str) -> bool:
        """Validate email format.

        Args:
            email: Email address to validate.

        Returns:
            True if email format is valid, False otherwise.
        """
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, email))


__all__ = [
    "GPGKey",
    "Profile",
    "SSHKey",
]
