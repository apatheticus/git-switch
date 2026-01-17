"""Import/Export service for Git-Switch.

This module provides functionality to export profiles to encrypted .gps archives
and import them back with merge/replace options and conflict resolution.

Archive Format (.gps):
    [4 bytes] Magic: "GSEX" (Git-Switch EXport)
    [4 bytes] Version: uint32 (1)
    [32 bytes] Salt for archive password
    [12 bytes] Nonce
    [N bytes] Encrypted ZIP ciphertext
    [16 bytes] GCM auth tag
"""

from __future__ import annotations

import io
import json
import logging
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from src.core.crypto import NONCE_LENGTH, SALT_LENGTH, secure_zero
from src.models.exceptions import (
    ArchivePasswordError,
    EncryptionError,
    InvalidArchiveError,
    SessionExpiredError,
)

if TYPE_CHECKING:
    from pathlib import Path
    from uuid import UUID

    from src.core.protocols import (
        CryptoServiceProtocol,
        ProfileManagerProtocol,
        RepositoryManagerProtocol,
        SessionManagerProtocol,
    )
    from src.models.profile import Profile

logger = logging.getLogger(__name__)

# Archive format constants
ARCHIVE_MAGIC = b"GSEX"  # Git-Switch EXport
ARCHIVE_VERSION = 1
MINIMUM_ARCHIVE_SIZE = 4 + 4 + SALT_LENGTH + NONCE_LENGTH + 16


@dataclass
class ExportResult:
    """Result of export operation.

    Attributes:
        file_path: Path to the created archive file.
        profile_count: Number of profiles exported.
        repository_count: Number of repository assignments exported.
        file_size: Size of the archive file in bytes.
    """

    file_path: Path
    profile_count: int
    repository_count: int
    file_size: int


@dataclass
class ImportResult:
    """Result of import operation.

    Attributes:
        imported_profiles: List of successfully imported profiles.
        skipped_profiles: Names of profiles that were skipped.
        renamed_profiles: Mapping of original name to new name for renamed profiles.
        imported_repositories: Number of repository assignments imported.
    """

    imported_profiles: list[Profile]
    skipped_profiles: list[str]
    renamed_profiles: dict[str, str]
    imported_repositories: int


class ImportExportService:
    """Service for importing and exporting profiles.

    Handles encryption/decryption of .gps archive files and
    manages profile data during import/export operations.
    """

    def __init__(
        self,
        session_manager: SessionManagerProtocol,
        crypto_service: CryptoServiceProtocol,
        profile_manager: ProfileManagerProtocol,
        repository_manager: RepositoryManagerProtocol | None = None,
    ) -> None:
        """Initialize the import/export service.

        Args:
            session_manager: Service for session state management.
            crypto_service: Service for cryptographic operations.
            profile_manager: Service for profile management.
            repository_manager: Service for repository management (optional).
        """
        self._session = session_manager
        self._crypto = crypto_service
        self._profile_manager = profile_manager
        self._repository_manager = repository_manager

    def _require_unlocked(self) -> None:
        """Ensure session is unlocked.

        Raises:
            SessionExpiredError: If session is locked.
        """
        if not self._session.is_unlocked:
            raise SessionExpiredError("Session is locked. Please unlock first.")

    def export_profiles(
        self,
        file_path: Path,
        archive_password: str,
        profile_ids: list[UUID] | None = None,
        include_repositories: bool = True,
    ) -> ExportResult:
        """Export profiles to an encrypted .gps archive.

        Args:
            file_path: Path where the archive will be created.
            archive_password: Password to encrypt the archive.
            profile_ids: Specific profile IDs to export (None = all).
            include_repositories: Whether to include repository assignments.

        Returns:
            ExportResult with export details.

        Raises:
            SessionExpiredError: If session is locked.
        """
        self._require_unlocked()

        # Get profiles to export
        all_profiles = self._profile_manager.list_profiles()
        if profile_ids is not None:
            profiles = [p for p in all_profiles if p.id in profile_ids]
        else:
            profiles = all_profiles

        # Get repository assignments if requested
        repositories = []
        if include_repositories and self._repository_manager is not None:
            repositories = self._repository_manager.list_repositories()
            # Only include repositories with profile assignments
            repositories = [r for r in repositories if r.assigned_profile_id is not None]

        # Create archive in memory
        archive_data = self._create_archive(
            profiles=profiles,
            repositories=repositories,
            archive_password=archive_password,
        )

        # Write to file
        file_path.write_bytes(archive_data)

        logger.info(f"Exported {len(profiles)} profiles to {file_path}")

        return ExportResult(
            file_path=file_path,
            profile_count=len(profiles),
            repository_count=len(repositories),
            file_size=len(archive_data),
        )

    def _create_archive(
        self,
        profiles: list[Profile],
        repositories: list[Any],
        archive_password: str,
    ) -> bytes:
        """Create encrypted archive data.

        Args:
            profiles: Profiles to include.
            repositories: Repository assignments to include.
            archive_password: Password for archive encryption.

        Returns:
            Complete archive as bytes.
        """
        # Generate salt for archive password
        salt = self._crypto.generate_salt()

        # Derive archive encryption key from password
        archive_key = self._crypto.derive_key(archive_password, salt)

        # Create ZIP contents in memory
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            # Create manifest
            manifest = {
                "version": ARCHIVE_VERSION,
                "profile_count": len(profiles),
                "export_timestamp": datetime.now(tz=UTC).isoformat(),
                "has_repositories": len(repositories) > 0,
            }
            zf.writestr("manifest.json", json.dumps(manifest, indent=2))

            # Serialize profiles (without encrypted keys - those go separately)
            profiles_data = []
            for profile in profiles:
                profile_dict = self._serialize_profile(profile)
                profiles_data.append(profile_dict)

                # Export keys separately, re-encrypted with archive key
                self._export_profile_keys(zf, profile, archive_key)

            zf.writestr("profiles.json", json.dumps(profiles_data, indent=2))

            # Export repository assignments
            if repositories:
                repos_data = [self._serialize_repository(r) for r in repositories]
                zf.writestr("repositories.json", json.dumps(repos_data, indent=2))

        # Get ZIP bytes
        zip_data = zip_buffer.getvalue()

        # Encrypt the ZIP data
        encrypted_zip = self._crypto.encrypt(zip_data, archive_key)

        # Build archive: magic + version + salt + encrypted_data
        archive = bytearray()
        archive.extend(ARCHIVE_MAGIC)
        archive.extend(ARCHIVE_VERSION.to_bytes(4, "little"))
        archive.extend(salt)
        archive.extend(encrypted_zip)

        # Clean up sensitive data
        archive_key_array = bytearray(archive_key)
        secure_zero(archive_key_array)

        return bytes(archive)

    def _serialize_profile(self, profile: Profile) -> dict[str, Any]:
        """Serialize profile metadata to dictionary.

        Args:
            profile: Profile to serialize.

        Returns:
            Dictionary of profile data (without encrypted key content).
        """
        return {
            "id": str(profile.id),
            "name": profile.name,
            "git_username": profile.git_username,
            "git_email": profile.git_email,
            "organization": profile.organization,
            "created_at": profile.created_at.isoformat() if profile.created_at else None,
            "last_used": profile.last_used.isoformat() if profile.last_used else None,
            "ssh_key": {
                "public_key": profile.ssh_key.public_key.decode("utf-8", errors="replace")
                if profile.ssh_key else "",
                "fingerprint": profile.ssh_key.fingerprint if profile.ssh_key else "",
                "has_passphrase": profile.ssh_key.passphrase_encrypted is not None
                if profile.ssh_key else False,
            },
            "gpg_key": {
                "enabled": profile.gpg_key.enabled,
                "key_id": profile.gpg_key.key_id,
            },
        }

    def _export_profile_keys(
        self,
        zf: zipfile.ZipFile,
        profile: Profile,
        archive_key: bytes,
    ) -> None:
        """Export encrypted keys for a profile.

        Re-encrypts keys with archive key before adding to ZIP.

        Args:
            zf: ZipFile to write keys to.
            profile: Profile whose keys to export.
            archive_key: Key to encrypt keys with.
        """
        profile_id = str(profile.id)
        session_key = self._session.encryption_key

        # Export SSH key
        if profile.ssh_key:
            ssh_data = {
                "private_key": None,
                "passphrase": None,
            }

            # Decrypt with session key, re-encrypt with archive key
            try:
                decrypted_private = self._crypto.decrypt(
                    profile.ssh_key.private_key_encrypted, session_key
                )
                encrypted_private = self._crypto.encrypt(decrypted_private, archive_key)
                ssh_data["private_key"] = encrypted_private.hex()

                # Clean up decrypted key
                decrypted_array = bytearray(decrypted_private)
                secure_zero(decrypted_array)
            except Exception:
                # If decryption fails, skip this key
                logger.warning(f"Failed to export SSH key for profile {profile.name}")

            # Handle passphrase if present
            if profile.ssh_key.passphrase_encrypted:
                try:
                    decrypted_passphrase = self._crypto.decrypt(
                        profile.ssh_key.passphrase_encrypted, session_key
                    )
                    encrypted_passphrase = self._crypto.encrypt(
                        decrypted_passphrase, archive_key
                    )
                    ssh_data["passphrase"] = encrypted_passphrase.hex()

                    passphrase_array = bytearray(decrypted_passphrase)
                    secure_zero(passphrase_array)
                except Exception as e:
                    logger.debug(f"No passphrase for profile {profile.name}: {e}")

            zf.writestr(f"keys/{profile_id}.ssh", json.dumps(ssh_data))

        # Export GPG key
        if profile.gpg_key.enabled and profile.gpg_key.private_key_encrypted:
            gpg_data = {
                "private_key": None,
                "public_key": profile.gpg_key.public_key.decode("utf-8", errors="replace")
                if profile.gpg_key.public_key else None,
            }

            try:
                decrypted_gpg = self._crypto.decrypt(
                    profile.gpg_key.private_key_encrypted, session_key
                )
                encrypted_gpg = self._crypto.encrypt(decrypted_gpg, archive_key)
                gpg_data["private_key"] = encrypted_gpg.hex()

                gpg_array = bytearray(decrypted_gpg)
                secure_zero(gpg_array)
            except Exception:
                logger.warning(f"Failed to export GPG key for profile {profile.name}")

            zf.writestr(f"keys/{profile_id}.gpg", json.dumps(gpg_data))

    def _serialize_repository(self, repo: Any) -> dict[str, Any]:
        """Serialize repository assignment to dictionary.

        Args:
            repo: Repository to serialize.

        Returns:
            Dictionary of repository data.
        """
        return {
            "id": str(repo.id),
            "path": str(repo.path),
            "name": repo.name,
            "assigned_profile_id": str(repo.assigned_profile_id)
            if repo.assigned_profile_id else None,
            "use_local_config": repo.use_local_config,
        }

    def import_profiles(
        self,
        file_path: Path,
        archive_password: str,
        mode: str = "merge",
        conflict_resolution: str = "rename",
    ) -> ImportResult:
        """Import profiles from an encrypted .gps archive.

        Args:
            file_path: Path to the archive file.
            archive_password: Password to decrypt the archive.
            mode: Import mode - "merge" or "replace".
            conflict_resolution: How to handle conflicts - "rename", "skip", "overwrite".

        Returns:
            ImportResult with import details.

        Raises:
            SessionExpiredError: If session is locked.
            FileNotFoundError: If archive file doesn't exist.
            InvalidArchiveError: If archive is invalid or corrupted.
            ArchivePasswordError: If password is incorrect.
        """
        self._require_unlocked()

        if not file_path.exists():
            raise FileNotFoundError(f"Archive file not found: {file_path}")

        # Read and validate archive
        archive_data = file_path.read_bytes()
        profiles_data, _repositories_data, archive_key = self._read_archive(
            archive_data, archive_password
        )

        try:
            # Handle replace mode - delete all existing profiles
            if mode == "replace":
                existing_profiles = self._profile_manager.list_profiles()
                for profile in existing_profiles:
                    try:
                        self._profile_manager.delete_profile(profile.id)
                    except Exception as e:
                        logger.warning(f"Failed to delete profile {profile.name}: {e}")

            # Import profiles
            imported = []
            skipped = []
            renamed = {}

            existing_names = {p.name for p in self._profile_manager.list_profiles()}

            for profile_data in profiles_data:
                result = self._import_profile(
                    profile_data=profile_data,
                    archive_key=archive_key,
                    existing_names=existing_names,
                    conflict_resolution=conflict_resolution,
                    mode=mode,
                )

                if result["status"] == "imported":
                    imported.append(result["profile"])
                    existing_names.add(result["profile"].name)
                elif result["status"] == "skipped":
                    skipped.append(result["name"])
                elif result["status"] == "renamed":
                    imported.append(result["profile"])
                    renamed[result["original_name"]] = result["profile"].name
                    existing_names.add(result["profile"].name)

            # Import repository assignments (currently not fully implemented)
            repo_count = 0
            # Repository import would need path validation and profile ID mapping

            logger.info(
                f"Imported {len(imported)} profiles, skipped {len(skipped)}, "
                f"renamed {len(renamed)} from {file_path}"
            )

            return ImportResult(
                imported_profiles=imported,
                skipped_profiles=skipped,
                renamed_profiles=renamed,
                imported_repositories=repo_count,
            )

        finally:
            # Clean up archive key
            key_array = bytearray(archive_key)
            secure_zero(key_array)

    def _read_archive(
        self,
        archive_data: bytes,
        archive_password: str,
    ) -> tuple[list[dict], list[dict], bytes]:
        """Read and decrypt archive data.

        Args:
            archive_data: Raw archive bytes.
            archive_password: Password to decrypt.

        Returns:
            Tuple of (profiles_data, repositories_data, archive_key).

        Raises:
            InvalidArchiveError: If archive format is invalid.
            ArchivePasswordError: If password is incorrect.
        """
        # Check minimum size
        if len(archive_data) < MINIMUM_ARCHIVE_SIZE:
            raise InvalidArchiveError("Archive file is too short")

        # Check magic number
        magic = archive_data[:4]
        if magic != ARCHIVE_MAGIC:
            raise InvalidArchiveError(
                f"Invalid archive magic: expected {ARCHIVE_MAGIC!r}, got {magic!r}"
            )

        # Check version
        version = int.from_bytes(archive_data[4:8], "little")
        if version != ARCHIVE_VERSION:
            raise InvalidArchiveError(
                f"Unsupported archive version: {version} (expected {ARCHIVE_VERSION})"
            )

        # Extract salt and encrypted data
        salt = archive_data[8 : 8 + SALT_LENGTH]
        encrypted_data = archive_data[8 + SALT_LENGTH :]

        # Derive key from password
        archive_key = self._crypto.derive_key(archive_password, salt)

        # Decrypt the ZIP data
        try:
            zip_data = self._crypto.decrypt(encrypted_data, archive_key)
        except EncryptionError as e:
            raise ArchivePasswordError("Incorrect archive password or corrupted data") from e

        # Parse ZIP contents
        try:
            zip_buffer = io.BytesIO(zip_data)
            with zipfile.ZipFile(zip_buffer, "r") as zf:
                # Read manifest
                manifest_data = zf.read("manifest.json")
                manifest = json.loads(manifest_data.decode("utf-8"))

                # Read profiles
                profiles_data_raw = zf.read("profiles.json")
                profiles_data = json.loads(profiles_data_raw.decode("utf-8"))

                # Attach key data to profiles
                for profile_data in profiles_data:
                    profile_id = profile_data["id"]

                    # Load SSH key data
                    try:
                        ssh_data = json.loads(zf.read(f"keys/{profile_id}.ssh"))
                        profile_data["_ssh_key_data"] = ssh_data
                    except KeyError:
                        profile_data["_ssh_key_data"] = None

                    # Load GPG key data
                    try:
                        gpg_data = json.loads(zf.read(f"keys/{profile_id}.gpg"))
                        profile_data["_gpg_key_data"] = gpg_data
                    except KeyError:
                        profile_data["_gpg_key_data"] = None

                # Read repositories if present
                repositories_data = []
                if manifest.get("has_repositories"):
                    try:
                        repos_raw = zf.read("repositories.json")
                        repositories_data = json.loads(repos_raw.decode("utf-8"))
                    except KeyError:
                        pass

        except (zipfile.BadZipFile, json.JSONDecodeError, KeyError) as e:
            raise InvalidArchiveError(f"Corrupted archive data: {e}") from e

        return profiles_data, repositories_data, archive_key

    def _import_profile(
        self,
        profile_data: dict[str, Any],
        archive_key: bytes,
        existing_names: set[str],
        conflict_resolution: str,
        mode: str,
    ) -> dict[str, Any]:
        """Import a single profile from archive data.

        Args:
            profile_data: Profile dictionary from archive.
            archive_key: Key to decrypt profile keys.
            existing_names: Set of existing profile names.
            conflict_resolution: How to handle conflicts.
            mode: Import mode.

        Returns:
            Result dict with status and profile.
        """
        original_name = profile_data["name"]
        new_name = original_name

        # Check for conflict
        if original_name in existing_names and mode == "merge":
            if conflict_resolution == "skip":
                return {"status": "skipped", "name": original_name}
            if conflict_resolution == "rename":
                new_name = self._generate_unique_name(original_name, existing_names)
            elif conflict_resolution == "overwrite":
                # Delete existing profile with same name
                existing = self._profile_manager.list_profiles()
                for p in existing:
                    if p.name == original_name:
                        self._profile_manager.delete_profile(p.id)
                        existing_names.discard(original_name)
                        break

        # Decrypt and re-encrypt keys with archive key
        ssh_private_key = None
        ssh_public_key = None
        ssh_passphrase = None
        gpg_private_key = None
        gpg_public_key = None

        # Process SSH key
        ssh_key_data = profile_data.get("_ssh_key_data")
        if ssh_key_data and ssh_key_data.get("private_key"):
            try:
                encrypted_hex = ssh_key_data["private_key"]
                encrypted_bytes = bytes.fromhex(encrypted_hex)
                decrypted_private = self._crypto.decrypt(encrypted_bytes, archive_key)

                # Get public key from profile data
                ssh_public_key = profile_data.get("ssh_key", {}).get("public_key", "")
                if isinstance(ssh_public_key, str):
                    ssh_public_key = ssh_public_key.encode("utf-8")

                ssh_private_key = decrypted_private

                # Handle passphrase
                if ssh_key_data.get("passphrase"):
                    passphrase_hex = ssh_key_data["passphrase"]
                    passphrase_bytes = bytes.fromhex(passphrase_hex)
                    ssh_passphrase = self._crypto.decrypt(passphrase_bytes, archive_key)

            except Exception as e:
                logger.warning(f"Failed to decrypt SSH key for {original_name}: {e}")

        # Process GPG key
        gpg_key_data = profile_data.get("_gpg_key_data")
        gpg_enabled = profile_data.get("gpg_key", {}).get("enabled", False)
        gpg_key_id = profile_data.get("gpg_key", {}).get("key_id", "")

        if gpg_key_data and gpg_key_data.get("private_key") and gpg_enabled:
            try:
                encrypted_hex = gpg_key_data["private_key"]
                encrypted_bytes = bytes.fromhex(encrypted_hex)
                gpg_private_key = self._crypto.decrypt(encrypted_bytes, archive_key)

                if gpg_key_data.get("public_key"):
                    gpg_public_key = gpg_key_data["public_key"]
                    if isinstance(gpg_public_key, str):
                        gpg_public_key = gpg_public_key.encode("utf-8")

            except Exception as e:
                logger.warning(f"Failed to decrypt GPG key for {original_name}: {e}")
                gpg_enabled = False

        # Create the profile
        try:
            profile = self._profile_manager.create_profile(
                name=new_name,
                git_username=profile_data["git_username"],
                git_email=profile_data["git_email"],
                ssh_private_key=ssh_private_key,
                ssh_public_key=ssh_public_key,
                ssh_passphrase=ssh_passphrase.decode("utf-8") if ssh_passphrase else None,
                gpg_enabled=gpg_enabled,
                gpg_key_id=gpg_key_id if gpg_enabled else None,
                gpg_private_key=gpg_private_key,
                gpg_public_key=gpg_public_key,
            )
        except Exception:
            logger.exception("Failed to create profile %s", new_name)
            return {"status": "skipped", "name": original_name}

        if new_name != original_name:
            return {
                "status": "renamed",
                "profile": profile,
                "original_name": original_name,
            }
        return {"status": "imported", "profile": profile}

    def _generate_unique_name(self, name: str, existing: set[str]) -> str:
        """Generate a unique profile name.

        Args:
            name: Original name.
            existing: Set of existing names.

        Returns:
            Unique name with suffix if needed.
        """
        if name not in existing:
            return name

        # Try "(imported)" suffix first
        imported_name = f"{name} (imported)"
        if imported_name not in existing:
            return imported_name

        # Try numbered suffixes
        counter = 2
        while True:
            numbered_name = f"{name} ({counter})"
            if numbered_name not in existing:
                return numbered_name
            counter += 1
            if counter > 100:
                # Safety limit
                return f"{name} ({counter})"


__all__ = [
    "ARCHIVE_MAGIC",
    "ARCHIVE_VERSION",
    "ExportResult",
    "ImportExportService",
    "ImportResult",
]
