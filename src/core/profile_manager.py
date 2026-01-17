"""Profile management for Git-Switch.

Handles profile CRUD operations with encrypted storage.
"""

from __future__ import annotations

import base64
import json
import logging
import struct
import tempfile
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from src.models.exceptions import (
    ProfileNotFoundError,
    ProfileValidationError,
    SessionExpiredError,
)
from src.models.profile import GPGKey, Profile, SSHKey
from src.models.serialization import (
    GitSwitchEncoder,
    deserialize_datetime,
)
from src.utils.paths import (
    get_gpg_key_path,
    get_profiles_path,
    get_ssh_key_path,
)

if TYPE_CHECKING:
    from pathlib import Path

    from src.core.protocols import CryptoServiceProtocol, SessionManagerProtocol
    from src.services.protocols import (
        CredentialServiceProtocol,
        GitServiceProtocol,
        GPGServiceProtocol,
        SSHServiceProtocol,
    )

logger = logging.getLogger(__name__)


# profiles.dat magic number and version
PROFILES_MAGIC = b"GSPR"
PROFILES_VERSION = 1


class ProfileManager:
    """Manages Git profile CRUD operations.

    This class handles:
    - Creating, reading, updating, and deleting profiles
    - Encrypted storage of profiles and keys
    - Session validation for all operations
    - Switching between profiles (applying configuration)
    """

    def __init__(
        self,
        session_manager: SessionManagerProtocol,
        crypto_service: CryptoServiceProtocol,
        git_service: GitServiceProtocol | None = None,
        ssh_service: SSHServiceProtocol | None = None,
        gpg_service: GPGServiceProtocol | None = None,
        credential_service: CredentialServiceProtocol | None = None,
    ) -> None:
        """Initialize the profile manager.

        Args:
            session_manager: Service for session state management.
            crypto_service: Service for cryptographic operations.
            git_service: Service for Git configuration operations.
            ssh_service: Service for SSH agent operations.
            gpg_service: Service for GPG keyring operations.
            credential_service: Service for credential management.
        """
        self._session = session_manager
        self._crypto = crypto_service
        self._git_service = git_service
        self._ssh_service = ssh_service
        self._gpg_service = gpg_service
        self._credential_service = credential_service
        self._profiles: list[Profile] = []
        self._loaded = False

    def _check_session(self) -> bytes:
        """Verify session is unlocked and return encryption key.

        Returns:
            The session encryption key.

        Raises:
            SessionExpiredError: If session is locked.
        """
        if not self._session.is_unlocked:
            raise SessionExpiredError("Session is locked")
        key = self._session.encryption_key
        if key is None:
            raise SessionExpiredError("No encryption key available")
        return key

    def _ensure_loaded(self) -> None:
        """Ensure profiles are loaded from disk."""
        if not self._loaded:
            self._load_profiles()
            self._loaded = True

    def _load_profiles(self) -> None:
        """Load profiles from encrypted profiles.dat file."""
        key = self._check_session()
        profiles_path = get_profiles_path()

        if not profiles_path.exists():
            self._profiles = []
            return

        try:
            data = profiles_path.read_bytes()

            # Verify magic number
            if len(data) < 8:
                self._profiles = []
                return

            magic = data[:4]
            if magic != PROFILES_MAGIC:
                self._profiles = []
                return

            # Read version
            version = struct.unpack("<I", data[4:8])[0]
            if version != PROFILES_VERSION:
                # Future: handle version migration
                self._profiles = []
                return

            # Decrypt profile data
            encrypted_data = data[8:]
            if not encrypted_data:
                self._profiles = []
                return

            decrypted = self._crypto.decrypt(encrypted_data, key)
            profiles_json = json.loads(decrypted.decode("utf-8"))

            # Deserialize profiles
            self._profiles = []
            for profile_data in profiles_json:
                profile = self._deserialize_profile(profile_data)
                self._profiles.append(profile)

        except Exception:
            # If loading fails, start fresh
            self._profiles = []

    def _save_profiles(self) -> None:
        """Save profiles to encrypted profiles.dat file."""
        key = self._check_session()
        profiles_path = get_profiles_path()

        # Serialize profiles (without SSH/GPG key content - stored separately)
        profiles_data = []
        for profile in self._profiles:
            profile_dict = self._serialize_profile(profile)
            profiles_data.append(profile_dict)

        # Encrypt and write
        json_data = json.dumps(profiles_data, cls=GitSwitchEncoder)
        encrypted = self._crypto.encrypt(json_data.encode("utf-8"), key)

        # Write with magic number and version
        with profiles_path.open("wb") as f:
            f.write(PROFILES_MAGIC)
            f.write(struct.pack("<I", PROFILES_VERSION))
            f.write(encrypted)

    def _serialize_profile(self, profile: Profile) -> dict[str, Any]:
        """Serialize a profile to dictionary for JSON storage.

        Args:
            profile: Profile to serialize.

        Returns:
            Dictionary representation.
        """
        result: dict[str, Any] = {
            "id": str(profile.id),
            "name": profile.name,
            "git_username": profile.git_username,
            "git_email": profile.git_email,
            "organization": profile.organization,
            "created_at": profile.created_at.isoformat(),
            "last_used": profile.last_used.isoformat() if profile.last_used else None,
            "is_active": profile.is_active,
        }

        # SSH key metadata only (content stored in separate file)
        if profile.ssh_key:
            result["ssh_key"] = {
                "fingerprint": profile.ssh_key.fingerprint,
                "public_key": base64.b64encode(profile.ssh_key.public_key).decode(
                    "ascii"
                ),
            }

        # GPG key metadata only (content stored in separate file)
        result["gpg_key"] = {
            "enabled": profile.gpg_key.enabled,
            "key_id": profile.gpg_key.key_id,
        }

        return result

    def _deserialize_profile(self, data: dict[str, Any]) -> Profile:
        """Deserialize a profile from dictionary.

        Args:
            data: Dictionary from JSON.

        Returns:
            Profile object.
        """
        profile_id = UUID(data["id"])

        # Load SSH key from separate file
        ssh_key = None
        if "ssh_key" in data:
            ssh_key = self._load_ssh_key(profile_id, data["ssh_key"])

        # Load GPG key metadata
        gpg_key = GPGKey(
            enabled=data.get("gpg_key", {}).get("enabled", False),
            key_id=data.get("gpg_key", {}).get("key_id", ""),
        )
        if gpg_key.enabled:
            gpg_key = self._load_gpg_key(profile_id, gpg_key)

        return Profile(
            id=profile_id,
            name=data["name"],
            git_username=data["git_username"],
            git_email=data["git_email"],
            organization=data.get("organization", ""),
            ssh_key=ssh_key,
            gpg_key=gpg_key,
            created_at=deserialize_datetime(data["created_at"]),
            last_used=(
                deserialize_datetime(data["last_used"]) if data.get("last_used") else None
            ),
            is_active=data.get("is_active", False),
        )

    def _load_ssh_key(
        self, profile_id: UUID, metadata: dict[str, Any]
    ) -> SSHKey | None:
        """Load SSH key from encrypted file.

        Args:
            profile_id: Profile UUID.
            metadata: SSH key metadata from profile.

        Returns:
            SSHKey object or None if not found.
        """
        key = self._check_session()
        ssh_path = get_ssh_key_path(str(profile_id))

        if not ssh_path.exists():
            return None

        try:
            encrypted_data = ssh_path.read_bytes()
            decrypted = self._crypto.decrypt(encrypted_data, key)
            key_data = json.loads(decrypted.decode("utf-8"))

            private_key = base64.b64decode(key_data["private_key"])
            passphrase_encrypted = (
                base64.b64decode(key_data["passphrase"])
                if key_data.get("passphrase")
                else None
            )

            return SSHKey(
                private_key_encrypted=private_key,
                public_key=base64.b64decode(metadata["public_key"]),
                passphrase_encrypted=passphrase_encrypted,
                fingerprint=metadata.get("fingerprint", ""),
            )
        except Exception:
            return None

    def _save_ssh_key(
        self, profile_id: UUID, ssh_key: SSHKey, passphrase: str | None = None
    ) -> None:
        """Save SSH key to encrypted file.

        Args:
            profile_id: Profile UUID.
            ssh_key: SSHKey with private key bytes (not yet encrypted).
            passphrase: Optional passphrase for the SSH key.
        """
        key = self._check_session()
        ssh_path = get_ssh_key_path(str(profile_id))

        # Encrypt the private key
        encrypted_private = self._crypto.encrypt(ssh_key.private_key_encrypted, key)

        # Encrypt passphrase if provided
        encrypted_passphrase = None
        if passphrase:
            encrypted_passphrase = self._crypto.encrypt(
                passphrase.encode("utf-8"), key
            )

        key_data = {
            "private_key": base64.b64encode(encrypted_private).decode("ascii"),
            "passphrase": (
                base64.b64encode(encrypted_passphrase).decode("ascii")
                if encrypted_passphrase
                else None
            ),
        }

        # Encrypt the whole key file
        json_data = json.dumps(key_data)
        encrypted = self._crypto.encrypt(json_data.encode("utf-8"), key)
        ssh_path.write_bytes(encrypted)

    def _load_gpg_key(self, profile_id: UUID, gpg_key: GPGKey) -> GPGKey:
        """Load GPG key from encrypted file.

        Args:
            profile_id: Profile UUID.
            gpg_key: GPGKey with metadata.

        Returns:
            GPGKey with loaded data.
        """
        if not gpg_key.enabled:
            return gpg_key

        key = self._check_session()
        gpg_path = get_gpg_key_path(str(profile_id))

        if not gpg_path.exists():
            return gpg_key

        try:
            encrypted_data = gpg_path.read_bytes()
            decrypted = self._crypto.decrypt(encrypted_data, key)
            key_data = json.loads(decrypted.decode("utf-8"))

            return GPGKey(
                enabled=True,
                key_id=gpg_key.key_id,
                private_key_encrypted=base64.b64decode(key_data["private_key"]),
                public_key=(
                    base64.b64decode(key_data["public_key"])
                    if key_data.get("public_key")
                    else None
                ),
            )
        except Exception:
            return gpg_key

    def _save_gpg_key(
        self,
        profile_id: UUID,
        gpg_private_key: bytes,
        gpg_public_key: bytes | None = None,
    ) -> None:
        """Save GPG key to encrypted file.

        Args:
            profile_id: Profile UUID.
            gpg_private_key: GPG private key bytes.
            gpg_public_key: GPG public key bytes.
        """
        key = self._check_session()
        gpg_path = get_gpg_key_path(str(profile_id))

        # Encrypt the private key
        encrypted_private = self._crypto.encrypt(gpg_private_key, key)

        key_data: dict[str, str | None] = {
            "private_key": base64.b64encode(encrypted_private).decode("ascii"),
            "public_key": (
                base64.b64encode(gpg_public_key).decode("ascii")
                if gpg_public_key
                else None
            ),
        }

        # Encrypt the whole key file
        json_data = json.dumps(key_data)
        encrypted = self._crypto.encrypt(json_data.encode("utf-8"), key)
        gpg_path.write_bytes(encrypted)

    def _delete_key_files(self, profile_id: UUID) -> None:
        """Delete key files for a profile.

        Args:
            profile_id: Profile UUID.
        """
        ssh_path = get_ssh_key_path(str(profile_id))
        gpg_path = get_gpg_key_path(str(profile_id))

        if ssh_path.exists():
            self._crypto.secure_delete_file(ssh_path)

        if gpg_path.exists():
            self._crypto.secure_delete_file(gpg_path)

    def list_profiles(self) -> list[Profile]:
        """Get all profiles.

        Returns:
            List of Profile objects.

        Raises:
            SessionExpiredError: If session is locked.
        """
        self._check_session()
        self._ensure_loaded()
        return list(self._profiles)

    def get_profile(self, profile_id: UUID) -> Profile | None:
        """Get a specific profile by ID.

        Args:
            profile_id: Profile UUID.

        Returns:
            Profile if found, None otherwise.

        Raises:
            SessionExpiredError: If session is locked.
        """
        self._check_session()
        self._ensure_loaded()

        for profile in self._profiles:
            if profile.id == profile_id:
                return profile
        return None

    def get_active_profile(self) -> Profile | None:
        """Get the currently active profile.

        Returns:
            Active Profile if one is set, None otherwise.

        Raises:
            SessionExpiredError: If session is locked.
        """
        self._check_session()
        self._ensure_loaded()

        for profile in self._profiles:
            if profile.is_active:
                return profile
        return None

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
        self._check_session()
        self._ensure_loaded()

        # Generate profile ID
        profile_id = uuid4()

        # Create SSH key object (with raw private key for now)
        ssh_key = SSHKey(
            private_key_encrypted=ssh_private_key,  # Will be encrypted when saved
            public_key=ssh_public_key,
            fingerprint="",  # TODO: Calculate fingerprint in Phase 4
        )

        # Create GPG key object
        gpg_key = GPGKey(enabled=False)
        if gpg_enabled:
            if not gpg_key_id or not gpg_private_key:
                raise ProfileValidationError(
                    "GPG key ID and private key required when GPG is enabled"
                )
            gpg_key = GPGKey(
                enabled=True,
                key_id=gpg_key_id,
                private_key_encrypted=gpg_private_key,  # Will be encrypted when saved
                public_key=gpg_public_key,
            )

        # Create profile (this will validate all fields)
        try:
            profile = Profile(
                id=profile_id,
                name=name,
                git_username=git_username,
                git_email=git_email,
                organization=organization or "",
                ssh_key=ssh_key,
                gpg_key=gpg_key,
                created_at=datetime.now(tz=UTC),
            )
        except ValueError as e:
            raise ProfileValidationError(str(e)) from e

        # Save SSH key to encrypted file
        self._save_ssh_key(profile_id, ssh_key, ssh_passphrase)

        # Save GPG key if enabled
        if gpg_enabled and gpg_private_key:
            self._save_gpg_key(profile_id, gpg_private_key, gpg_public_key)

        # Add to list and save
        self._profiles.append(profile)
        self._save_profiles()

        return profile

    def update_profile(
        self,
        profile_id: UUID,
        **kwargs: Any,
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
        self._check_session()
        self._ensure_loaded()

        # Find profile
        profile_idx = None
        for i, p in enumerate(self._profiles):
            if p.id == profile_id:
                profile_idx = i
                break

        if profile_idx is None:
            raise ProfileNotFoundError(f"Profile not found: {profile_id}")

        old_profile = self._profiles[profile_idx]

        # Handle SSH key update
        ssh_key = old_profile.ssh_key
        ssh_private_key = kwargs.pop("ssh_private_key", None)
        ssh_public_key = kwargs.pop("ssh_public_key", None)
        ssh_passphrase = kwargs.pop("ssh_passphrase", None)

        if ssh_private_key is not None and ssh_public_key is not None:
            ssh_key = SSHKey(
                private_key_encrypted=ssh_private_key,
                public_key=ssh_public_key,
                fingerprint="",
            )
            self._save_ssh_key(profile_id, ssh_key, ssh_passphrase)

        # Handle GPG key update
        gpg_key = old_profile.gpg_key
        gpg_enabled = kwargs.pop("gpg_enabled", None)
        gpg_key_id = kwargs.pop("gpg_key_id", None)
        gpg_private_key = kwargs.pop("gpg_private_key", None)
        gpg_public_key = kwargs.pop("gpg_public_key", None)

        if gpg_enabled is not None:
            if gpg_enabled:
                if not gpg_key_id or not gpg_private_key:
                    raise ProfileValidationError(
                        "GPG key ID and private key required when GPG is enabled"
                    )
                gpg_key = GPGKey(
                    enabled=True,
                    key_id=gpg_key_id,
                    private_key_encrypted=gpg_private_key,
                    public_key=gpg_public_key,
                )
                self._save_gpg_key(profile_id, gpg_private_key, gpg_public_key)
            else:
                gpg_key = GPGKey(enabled=False)

        # Create updated profile
        try:
            updated_profile = Profile(
                id=profile_id,
                name=kwargs.get("name", old_profile.name),
                git_username=kwargs.get("git_username", old_profile.git_username),
                git_email=kwargs.get("git_email", old_profile.git_email),
                organization=kwargs.get("organization", old_profile.organization),
                ssh_key=ssh_key,
                gpg_key=gpg_key,
                created_at=old_profile.created_at,
                last_used=old_profile.last_used,
                is_active=kwargs.get("is_active", old_profile.is_active),
            )
        except ValueError as e:
            raise ProfileValidationError(str(e)) from e

        # Update in list and save
        self._profiles[profile_idx] = updated_profile
        self._save_profiles()

        return updated_profile

    def delete_profile(self, profile_id: UUID) -> None:
        """Delete a profile.

        Args:
            profile_id: Profile UUID.

        Raises:
            ProfileNotFoundError: If profile doesn't exist.
            SessionExpiredError: If session is locked.
        """
        self._check_session()
        self._ensure_loaded()

        # Find profile
        profile_idx = None
        for i, p in enumerate(self._profiles):
            if p.id == profile_id:
                profile_idx = i
                break

        if profile_idx is None:
            raise ProfileNotFoundError(f"Profile not found: {profile_id}")

        # Delete key files
        self._delete_key_files(profile_id)

        # Remove from list and save
        del self._profiles[profile_idx]
        self._save_profiles()

    def switch_profile(
        self,
        profile_id: UUID,
        scope: str = "global",
        repo_path: Path | None = None,
    ) -> None:
        """Switch to a profile (apply configuration).

        This method:
        1. Clears cached Git credentials
        2. Updates Git configuration (global or local)
        3. Loads SSH key into ssh-agent
        4. Imports GPG key if enabled
        5. Updates profile state (active, last_used)

        Args:
            profile_id: UUID of the profile to switch to.
            scope: "global" for global config, "local" for repository config.
            repo_path: Required when scope is "local".

        Raises:
            ProfileNotFoundError: If profile doesn't exist.
            SessionExpiredError: If session is locked.
            SSHServiceError: If SSH key operations fail.
            GPGServiceError: If GPG key operations fail.
            GitServiceError: If Git config operations fail.
        """
        self._check_session()
        self._ensure_loaded()

        # Find profile
        profile = self.get_profile(profile_id)
        if not profile:
            raise ProfileNotFoundError(f"Profile not found: {profile_id}")

        # 1. Clear cached Git credentials
        if self._credential_service:
            try:
                cleared = self._credential_service.clear_git_credentials()
                if cleared:
                    logger.info(f"Cleared {len(cleared)} cached credentials")
            except Exception as e:
                logger.warning(f"Failed to clear credentials: {e}")

        # 2. Update Git configuration
        if self._git_service:
            signing_key = profile.gpg_key.key_id if profile.gpg_key.enabled else None
            gpg_sign = profile.gpg_key.enabled

            if scope == "local" and repo_path:
                self._git_service.set_local_config(
                    repo_path=repo_path,
                    username=profile.git_username,
                    email=profile.git_email,
                    signing_key=signing_key,
                    gpg_sign=gpg_sign,
                )
                logger.info(f"Updated local Git config for {repo_path}")
            else:
                self._git_service.set_global_config(
                    username=profile.git_username,
                    email=profile.git_email,
                    signing_key=signing_key,
                    gpg_sign=gpg_sign,
                )
                logger.info("Updated global Git config")

        # 3. Load SSH key into agent
        if self._ssh_service and profile.ssh_key:
            # Remove all existing keys from agent
            self._ssh_service.remove_all_keys()

            # Write private key to temp file and add to agent
            ssh_key = profile.ssh_key
            private_key = self._decrypt_ssh_key(profile_id, ssh_key)
            passphrase = self._get_ssh_passphrase(profile_id, ssh_key)

            if private_key:
                self._add_ssh_key_to_agent(private_key, passphrase)

        # 4. Import GPG key if enabled
        if self._gpg_service and profile.gpg_key.enabled:
            gpg_key = profile.gpg_key
            if gpg_key.private_key_encrypted:
                # Decrypt GPG key
                gpg_private_key = self._decrypt_gpg_key(profile_id, gpg_key)
                if gpg_private_key:
                    try:
                        self._gpg_service.import_key(gpg_private_key)
                        logger.info(f"Imported GPG key {gpg_key.key_id}")
                    except Exception as e:
                        logger.warning(f"Failed to import GPG key: {e}")

        # 5. Update profile state
        self._deactivate_all_profiles()

        # Find and update the profile
        for i, p in enumerate(self._profiles):
            if p.id == profile_id:
                # Create updated profile with new state
                self._profiles[i] = Profile(
                    id=p.id,
                    name=p.name,
                    git_username=p.git_username,
                    git_email=p.git_email,
                    organization=p.organization,
                    ssh_key=p.ssh_key,
                    gpg_key=p.gpg_key,
                    created_at=p.created_at,
                    last_used=datetime.now(tz=UTC),
                    is_active=True,
                )
                break

        self._save_profiles()
        logger.info(f"Switched to profile: {profile.name}")

        # Show notification
        try:
            from src.utils.notifications import show_profile_switch_notification

            show_profile_switch_notification(
                profile_name=profile.name,
                organization=profile.organization if profile.organization else None,
            )
        except Exception as e:
            logger.debug(f"Failed to show notification: {e}")

    def _deactivate_all_profiles(self) -> None:
        """Deactivate all profiles."""
        for i, p in enumerate(self._profiles):
            if p.is_active:
                self._profiles[i] = Profile(
                    id=p.id,
                    name=p.name,
                    git_username=p.git_username,
                    git_email=p.git_email,
                    organization=p.organization,
                    ssh_key=p.ssh_key,
                    gpg_key=p.gpg_key,
                    created_at=p.created_at,
                    last_used=p.last_used,
                    is_active=False,
                )

    def _decrypt_ssh_key(self, profile_id: UUID, ssh_key: SSHKey) -> bytes | None:
        """Decrypt the SSH private key from storage.

        Args:
            profile_id: Profile UUID.
            ssh_key: SSHKey object with encrypted data.

        Returns:
            Decrypted private key bytes, or None if not available.
        """
        key = self._check_session()
        ssh_path = get_ssh_key_path(str(profile_id))

        if not ssh_path.exists():
            return None

        try:
            encrypted_data = ssh_path.read_bytes()
            decrypted = self._crypto.decrypt(encrypted_data, key)
            key_data = json.loads(decrypted.decode("utf-8"))

            # The private key is double-encrypted: once in key_data, once in file
            encrypted_private = base64.b64decode(key_data["private_key"])
            return self._crypto.decrypt(encrypted_private, key)
        except Exception as e:
            logger.warning(f"Failed to decrypt SSH key: {e}")
            return None

    def _get_ssh_passphrase(self, profile_id: UUID, ssh_key: SSHKey) -> str | None:
        """Get the SSH key passphrase.

        Args:
            profile_id: Profile UUID.
            ssh_key: SSHKey object.

        Returns:
            Decrypted passphrase, or None if not set.
        """
        key = self._check_session()
        ssh_path = get_ssh_key_path(str(profile_id))

        if not ssh_path.exists():
            return None

        try:
            encrypted_data = ssh_path.read_bytes()
            decrypted = self._crypto.decrypt(encrypted_data, key)
            key_data = json.loads(decrypted.decode("utf-8"))

            if not key_data.get("passphrase"):
                return None

            encrypted_passphrase = base64.b64decode(key_data["passphrase"])
            decrypted_passphrase = self._crypto.decrypt(encrypted_passphrase, key)
            return decrypted_passphrase.decode("utf-8")
        except Exception as e:
            logger.warning(f"Failed to get SSH passphrase: {e}")
            return None

    def _add_ssh_key_to_agent(
        self, private_key: bytes, passphrase: str | None = None
    ) -> None:
        """Add SSH key to agent via temp file.

        Args:
            private_key: Decrypted private key bytes.
            passphrase: Optional passphrase.
        """
        import os
        from pathlib import Path as PathType

        if not self._ssh_service:
            return

        # Write key to temp file
        fd, temp_path = tempfile.mkstemp(suffix=".key", prefix="gs_")
        try:
            os.write(fd, private_key)
            os.close(fd)

            # Set restrictive permissions (Windows doesn't fully support this)
            temp_file = PathType(temp_path)

            # Add to agent
            self._ssh_service.add_key(temp_file, passphrase)
            logger.info("Added SSH key to agent")
        finally:
            # Securely delete temp file
            try:
                os.unlink(temp_path)
            except Exception:
                pass

    def _decrypt_gpg_key(self, profile_id: UUID, gpg_key: GPGKey) -> bytes | None:
        """Decrypt the GPG private key from storage.

        Args:
            profile_id: Profile UUID.
            gpg_key: GPGKey object with encrypted data.

        Returns:
            Decrypted private key bytes, or None if not available.
        """
        key = self._check_session()
        gpg_path = get_gpg_key_path(str(profile_id))

        if not gpg_path.exists():
            return None

        try:
            encrypted_data = gpg_path.read_bytes()
            decrypted = self._crypto.decrypt(encrypted_data, key)
            key_data = json.loads(decrypted.decode("utf-8"))

            # The private key is double-encrypted
            encrypted_private = base64.b64decode(key_data["private_key"])
            return self._crypto.decrypt(encrypted_private, key)
        except Exception as e:
            logger.warning(f"Failed to decrypt GPG key: {e}")
            return None

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

        NOT IMPLEMENTED IN PHASE 3 - will be implemented in Phase 10 (US8).

        Raises:
            NotImplementedError: Always.
        """
        raise NotImplementedError(
            "validate_credentials will be implemented in Phase 10 (US8)"
        )


__all__ = [
    "PROFILES_MAGIC",
    "PROFILES_VERSION",
    "ProfileManager",
]
