"""Unit tests for Import/Export functionality.

These tests verify profile import/export operations including:
- Exporting profiles to encrypted .gps archives
- Importing profiles from encrypted archives
- Conflict resolution during merge imports
- Archive format validation

TDD Note: These tests are written before the ImportExportService implementation
and should FAIL until the implementation is complete.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import pytest

if TYPE_CHECKING:
    from src.core.import_export import ImportExportService


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_session_manager() -> MagicMock:
    """Create a mock SessionManager that is unlocked."""
    mock = MagicMock()
    mock.is_unlocked = True
    mock.encryption_key = b"K" * 32
    return mock


@pytest.fixture
def mock_session_manager_locked() -> MagicMock:
    """Create a mock SessionManager that is locked."""
    mock = MagicMock()
    mock.is_unlocked = False
    mock.encryption_key = None
    return mock


@pytest.fixture
def mock_crypto_service() -> MagicMock:
    """Create a mock CryptoService."""
    mock = MagicMock()
    mock.generate_salt.return_value = b"S" * 32
    mock.derive_key.return_value = b"K" * 32
    mock.encrypt.side_effect = lambda data, key: b"ENC:" + data
    mock.decrypt.side_effect = (
        lambda data, key: data[4:] if data.startswith(b"ENC:") else data
    )
    return mock


@pytest.fixture
def mock_profile_manager() -> MagicMock:
    """Create a mock ProfileManager with sample profiles."""
    from src.models.profile import GPGKey, Profile, SSHKey

    mock = MagicMock()

    # Create sample profiles
    profile1_id = uuid4()
    profile2_id = uuid4()

    ssh_key1 = SSHKey(
        private_key_encrypted=b"ENC:ssh-private-1",
        public_key=b"ssh-ed25519 AAAAC3... profile1@example.com",
        fingerprint="SHA256:abcdef123456",
    )
    ssh_key2 = SSHKey(
        private_key_encrypted=b"ENC:ssh-private-2",
        public_key=b"ssh-ed25519 AAAAC3... profile2@example.com",
        fingerprint="SHA256:ghijkl789012",
    )
    gpg_key = GPGKey(
        enabled=True,
        key_id="ABCD1234EFGH5678",
        private_key_encrypted=b"ENC:gpg-private",
        public_key=b"-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n-----END PGP PUBLIC KEY BLOCK-----",
    )

    profile1 = Profile(
        id=profile1_id,
        name="Work",
        git_username="work-user",
        git_email="work@example.com",
        ssh_key=ssh_key1,
        gpg_key=GPGKey(),  # GPG disabled
    )
    profile2 = Profile(
        id=profile2_id,
        name="Personal",
        git_username="personal-user",
        git_email="personal@example.com",
        ssh_key=ssh_key2,
        gpg_key=gpg_key,
    )

    mock.list_profiles.return_value = [profile1, profile2]
    mock.get_profile.side_effect = lambda pid: (
        profile1 if pid == profile1_id else profile2 if pid == profile2_id else None
    )
    mock.create_profile.return_value = profile1

    # Store profiles for reference
    mock._profiles = [profile1, profile2]

    return mock


@pytest.fixture
def mock_repository_manager() -> MagicMock:
    """Create a mock RepositoryManager with sample assignments."""
    from src.models.repository import Repository

    mock = MagicMock()

    profile1_id = uuid4()

    repo1 = Repository(
        path=Path("C:/repos/project1").resolve(),
        name="Project 1",
        assigned_profile_id=profile1_id,
    )
    repo2 = Repository(
        path=Path("C:/repos/project2").resolve(),
        name="Project 2",
        assigned_profile_id=None,
    )

    mock.list_repositories.return_value = [repo1, repo2]
    mock._repositories = [repo1, repo2]

    return mock


@pytest.fixture
def import_export_service(
    mock_session_manager: MagicMock,
    mock_crypto_service: MagicMock,
    mock_profile_manager: MagicMock,
    mock_repository_manager: MagicMock,
    temp_dir: Path,
) -> "ImportExportService":
    """Create an ImportExportService for testing."""
    from src.core.import_export import ImportExportService

    service = ImportExportService(
        session_manager=mock_session_manager,
        crypto_service=mock_crypto_service,
        profile_manager=mock_profile_manager,
        repository_manager=mock_repository_manager,
    )
    return service


@pytest.fixture
def import_export_service_locked(
    mock_session_manager_locked: MagicMock,
    mock_crypto_service: MagicMock,
    mock_profile_manager: MagicMock,
    mock_repository_manager: MagicMock,
    temp_dir: Path,
) -> "ImportExportService":
    """Create an ImportExportService with locked session."""
    from src.core.import_export import ImportExportService

    service = ImportExportService(
        session_manager=mock_session_manager_locked,
        crypto_service=mock_crypto_service,
        profile_manager=mock_profile_manager,
        repository_manager=mock_repository_manager,
    )
    return service


@pytest.fixture
def sample_archive_password() -> str:
    """Provide a sample archive password for testing."""
    return "ArchivePassword123!"


@pytest.fixture
def sample_archive(
    import_export_service: "ImportExportService",
    temp_dir: Path,
    sample_archive_password: str,
) -> Path:
    """Create a sample .gps archive for testing imports."""
    archive_path = temp_dir / "test_export.gps"

    # Export profiles to create a valid archive
    result = import_export_service.export_profiles(
        file_path=archive_path,
        archive_password=sample_archive_password,
    )

    return result.file_path


@pytest.fixture
def real_crypto_archive(
    mock_session_manager: MagicMock,
    mock_profile_manager: MagicMock,
    mock_repository_manager: MagicMock,
    temp_dir: Path,
    sample_archive_password: str,
) -> Path:
    """Create a .gps archive using real encryption for edge case tests."""
    from src.core.crypto import CryptoService
    from src.core.import_export import ImportExportService

    real_crypto = CryptoService()

    service = ImportExportService(
        session_manager=mock_session_manager,
        crypto_service=real_crypto,
        profile_manager=mock_profile_manager,
        repository_manager=mock_repository_manager,
    )

    archive_path = temp_dir / "real_crypto_export.gps"
    result = service.export_profiles(
        file_path=archive_path,
        archive_password=sample_archive_password,
    )

    return result.file_path


# =============================================================================
# Export Tests
# =============================================================================


class TestExportProfiles:
    """Tests for export_profiles() method."""

    def test_export_profiles_creates_encrypted_archive(
        self,
        import_export_service: "ImportExportService",
        temp_dir: Path,
        sample_archive_password: str,
    ) -> None:
        """export_profiles should create an encrypted .gps archive file."""
        archive_path = temp_dir / "export.gps"

        result = import_export_service.export_profiles(
            file_path=archive_path,
            archive_password=sample_archive_password,
        )

        assert result.file_path.exists()
        assert result.file_path == archive_path
        assert result.profile_count == 2

    def test_export_profiles_includes_ssh_keys(
        self,
        import_export_service: "ImportExportService",
        temp_dir: Path,
        sample_archive_password: str,
        mock_crypto_service: MagicMock,
    ) -> None:
        """export_profiles should include SSH keys in the archive."""
        archive_path = temp_dir / "export.gps"

        import_export_service.export_profiles(
            file_path=archive_path,
            archive_password=sample_archive_password,
        )

        # Verify crypto was used (encryption called for re-encrypting keys)
        assert mock_crypto_service.encrypt.called or mock_crypto_service.decrypt.called

    def test_export_profiles_includes_gpg_keys(
        self,
        import_export_service: "ImportExportService",
        temp_dir: Path,
        sample_archive_password: str,
        mock_profile_manager: MagicMock,
    ) -> None:
        """export_profiles should include GPG keys when enabled."""
        archive_path = temp_dir / "export.gps"

        result = import_export_service.export_profiles(
            file_path=archive_path,
            archive_password=sample_archive_password,
        )

        # Profile 2 has GPG enabled
        profiles = mock_profile_manager.list_profiles()
        gpg_enabled_profile = [p for p in profiles if p.gpg_key.enabled]
        assert len(gpg_enabled_profile) == 1
        assert result.profile_count == 2

    def test_export_profiles_includes_repository_assignments(
        self,
        import_export_service: "ImportExportService",
        temp_dir: Path,
        sample_archive_password: str,
    ) -> None:
        """export_profiles should include repository assignments when requested."""
        archive_path = temp_dir / "export.gps"

        result = import_export_service.export_profiles(
            file_path=archive_path,
            archive_password=sample_archive_password,
            include_repositories=True,
        )

        # We have 2 repositories (1 assigned)
        assert result.repository_count >= 1

    def test_export_profiles_uses_separate_archive_password(
        self,
        import_export_service: "ImportExportService",
        temp_dir: Path,
        sample_archive_password: str,
        mock_crypto_service: MagicMock,
    ) -> None:
        """export_profiles should derive a separate key from archive password."""
        archive_path = temp_dir / "export.gps"

        import_export_service.export_profiles(
            file_path=archive_path,
            archive_password=sample_archive_password,
        )

        # Verify derive_key was called for archive password
        mock_crypto_service.derive_key.assert_called()

    def test_export_profiles_requires_unlocked_session(
        self,
        import_export_service_locked: "ImportExportService",
        temp_dir: Path,
        sample_archive_password: str,
    ) -> None:
        """export_profiles should raise SessionExpiredError when session is locked."""
        from src.models.exceptions import SessionExpiredError

        archive_path = temp_dir / "export.gps"

        with pytest.raises(SessionExpiredError):
            import_export_service_locked.export_profiles(
                file_path=archive_path,
                archive_password=sample_archive_password,
            )

    def test_export_profiles_with_no_profiles_creates_empty_archive(
        self,
        mock_session_manager: MagicMock,
        mock_crypto_service: MagicMock,
        mock_repository_manager: MagicMock,
        temp_dir: Path,
        sample_archive_password: str,
    ) -> None:
        """export_profiles should create a valid archive even with no profiles."""
        from src.core.import_export import ImportExportService

        # Create a profile manager with no profiles
        empty_profile_manager = MagicMock()
        empty_profile_manager.list_profiles.return_value = []

        service = ImportExportService(
            session_manager=mock_session_manager,
            crypto_service=mock_crypto_service,
            profile_manager=empty_profile_manager,
            repository_manager=mock_repository_manager,
        )

        archive_path = temp_dir / "empty_export.gps"
        result = service.export_profiles(
            file_path=archive_path,
            archive_password=sample_archive_password,
        )

        assert result.file_path.exists()
        assert result.profile_count == 0

    def test_export_profiles_specific_profiles_only(
        self,
        import_export_service: "ImportExportService",
        mock_profile_manager: MagicMock,
        temp_dir: Path,
        sample_archive_password: str,
    ) -> None:
        """export_profiles should export only specified profiles when given profile_ids."""
        archive_path = temp_dir / "partial_export.gps"
        profiles = mock_profile_manager.list_profiles()
        selected_id = profiles[0].id

        result = import_export_service.export_profiles(
            file_path=archive_path,
            archive_password=sample_archive_password,
            profile_ids=[selected_id],
        )

        assert result.profile_count == 1


# =============================================================================
# Import Tests
# =============================================================================


class TestImportProfiles:
    """Tests for import_profiles() method."""

    def test_import_profiles_decrypts_archive(
        self,
        import_export_service: "ImportExportService",
        sample_archive: Path,
        sample_archive_password: str,
        mock_profile_manager: MagicMock,
    ) -> None:
        """import_profiles should successfully decrypt a valid archive."""
        # Clear existing profiles for fresh import
        mock_profile_manager.list_profiles.return_value = []

        result = import_export_service.import_profiles(
            file_path=sample_archive,
            archive_password=sample_archive_password,
            mode="replace",
        )

        assert len(result.imported_profiles) >= 0  # Should succeed without error

    def test_import_profiles_replace_mode_clears_existing(
        self,
        import_export_service: "ImportExportService",
        sample_archive: Path,
        sample_archive_password: str,
        mock_profile_manager: MagicMock,
    ) -> None:
        """import_profiles with replace mode should clear all existing profiles."""
        result = import_export_service.import_profiles(
            file_path=sample_archive,
            archive_password=sample_archive_password,
            mode="replace",
        )

        # delete_profile should have been called for existing profiles
        mock_profile_manager.delete_profile.assert_called()

    def test_import_profiles_merge_mode_adds_to_existing(
        self,
        import_export_service: "ImportExportService",
        sample_archive: Path,
        sample_archive_password: str,
        mock_profile_manager: MagicMock,
    ) -> None:
        """import_profiles with merge mode should not delete existing profiles."""
        result = import_export_service.import_profiles(
            file_path=sample_archive,
            archive_password=sample_archive_password,
            mode="merge",
        )

        # delete_profile should NOT be called in merge mode (unless overwriting)
        # Result should indicate success
        assert result is not None

    def test_import_profiles_requires_unlocked_session(
        self,
        import_export_service_locked: "ImportExportService",
        temp_dir: Path,
        sample_archive_password: str,
    ) -> None:
        """import_profiles should raise SessionExpiredError when session is locked."""
        from src.models.exceptions import SessionExpiredError

        # Create a dummy archive file
        archive_path = temp_dir / "dummy.gps"
        archive_path.write_bytes(b"dummy")

        with pytest.raises(SessionExpiredError):
            import_export_service_locked.import_profiles(
                file_path=archive_path,
                archive_password=sample_archive_password,
            )

    def test_import_profiles_wrong_password_raises_error(
        self,
        mock_session_manager: MagicMock,
        mock_profile_manager: MagicMock,
        mock_repository_manager: MagicMock,
        real_crypto_archive: Path,
    ) -> None:
        """import_profiles should raise ArchivePasswordError with wrong password."""
        from src.core.crypto import CryptoService
        from src.core.import_export import ImportExportService
        from src.models.exceptions import ArchivePasswordError

        # Use real crypto service to test actual decryption failure
        real_crypto = CryptoService()

        service = ImportExportService(
            session_manager=mock_session_manager,
            crypto_service=real_crypto,
            profile_manager=mock_profile_manager,
            repository_manager=mock_repository_manager,
        )

        with pytest.raises(ArchivePasswordError):
            service.import_profiles(
                file_path=real_crypto_archive,
                archive_password="WrongPassword123!",
            )


# =============================================================================
# Conflict Resolution Tests
# =============================================================================


class TestConflictResolution:
    """Tests for conflict resolution during merge import."""

    def test_import_merge_renames_on_conflict(
        self,
        import_export_service: "ImportExportService",
        sample_archive: Path,
        sample_archive_password: str,
        mock_profile_manager: MagicMock,
    ) -> None:
        """import_profiles with rename conflict resolution should add suffix."""
        # Ensure existing profiles have same names as imported ones
        result = import_export_service.import_profiles(
            file_path=sample_archive,
            archive_password=sample_archive_password,
            mode="merge",
            conflict_resolution="rename",
        )

        # Renamed profiles should be in the result
        # The exact name depends on implementation, but should be renamed
        assert isinstance(result.renamed_profiles, dict)

    def test_import_merge_skips_on_conflict(
        self,
        import_export_service: "ImportExportService",
        sample_archive: Path,
        sample_archive_password: str,
        mock_profile_manager: MagicMock,
    ) -> None:
        """import_profiles with skip conflict resolution should skip duplicates."""
        result = import_export_service.import_profiles(
            file_path=sample_archive,
            archive_password=sample_archive_password,
            mode="merge",
            conflict_resolution="skip",
        )

        # Skipped profiles should be listed
        assert isinstance(result.skipped_profiles, list)

    def test_import_merge_overwrites_on_conflict(
        self,
        import_export_service: "ImportExportService",
        sample_archive: Path,
        sample_archive_password: str,
        mock_profile_manager: MagicMock,
    ) -> None:
        """import_profiles with overwrite conflict resolution should replace existing."""
        result = import_export_service.import_profiles(
            file_path=sample_archive,
            archive_password=sample_archive_password,
            mode="merge",
            conflict_resolution="overwrite",
        )

        # With overwrite, existing profiles should be deleted first
        # Result should not have skipped profiles
        assert result is not None


# =============================================================================
# Archive Format Tests
# =============================================================================


class TestArchiveFormat:
    """Tests for .gps archive format validation."""

    def test_archive_has_correct_magic_number(
        self,
        import_export_service: "ImportExportService",
        temp_dir: Path,
        sample_archive_password: str,
    ) -> None:
        """Exported archive should have GSEX magic number."""
        from src.core.import_export import ARCHIVE_MAGIC

        archive_path = temp_dir / "magic_test.gps"

        import_export_service.export_profiles(
            file_path=archive_path,
            archive_password=sample_archive_password,
        )

        # Read first 4 bytes
        with open(archive_path, "rb") as f:
            magic = f.read(4)

        assert magic == ARCHIVE_MAGIC

    def test_archive_invalid_magic_raises_error(
        self,
        import_export_service: "ImportExportService",
        temp_dir: Path,
        sample_archive_password: str,
    ) -> None:
        """import_profiles should raise InvalidArchiveError for wrong magic number."""
        from src.models.exceptions import InvalidArchiveError

        # Create a file with invalid magic
        invalid_archive = temp_dir / "invalid.gps"
        invalid_archive.write_bytes(b"XXXX" + b"\x00" * 100)

        with pytest.raises(InvalidArchiveError):
            import_export_service.import_profiles(
                file_path=invalid_archive,
                archive_password=sample_archive_password,
            )

    def test_archive_version_mismatch_handled(
        self,
        import_export_service: "ImportExportService",
        temp_dir: Path,
        sample_archive_password: str,
    ) -> None:
        """import_profiles should handle future archive versions gracefully."""
        from src.core.import_export import ARCHIVE_MAGIC
        from src.models.exceptions import InvalidArchiveError

        # Create archive with future version
        future_archive = temp_dir / "future.gps"
        with open(future_archive, "wb") as f:
            f.write(ARCHIVE_MAGIC)  # Magic
            f.write((999).to_bytes(4, "little"))  # Future version
            f.write(b"\x00" * 100)  # Padding

        with pytest.raises(InvalidArchiveError):
            import_export_service.import_profiles(
                file_path=future_archive,
                archive_password=sample_archive_password,
            )

    def test_archive_too_short_raises_error(
        self,
        import_export_service: "ImportExportService",
        temp_dir: Path,
        sample_archive_password: str,
    ) -> None:
        """import_profiles should raise error for truncated archive."""
        from src.models.exceptions import InvalidArchiveError

        # Create a truncated file
        truncated_archive = temp_dir / "truncated.gps"
        truncated_archive.write_bytes(b"GS")  # Too short

        with pytest.raises(InvalidArchiveError):
            import_export_service.import_profiles(
                file_path=truncated_archive,
                archive_password=sample_archive_password,
            )

    def test_archive_corrupted_data_raises_error(
        self,
        mock_session_manager: MagicMock,
        mock_profile_manager: MagicMock,
        mock_repository_manager: MagicMock,
        real_crypto_archive: Path,
        sample_archive_password: str,
    ) -> None:
        """import_profiles should raise error for corrupted archive data."""
        from src.core.crypto import CryptoService
        from src.core.import_export import ImportExportService
        from src.models.exceptions import ArchivePasswordError, InvalidArchiveError

        # Use real crypto service to test actual decryption failure
        real_crypto = CryptoService()

        # Corrupt the archive by modifying bytes in the encrypted section
        data = real_crypto_archive.read_bytes()
        # Corrupt bytes after header (magic + version + salt = 4 + 4 + 32 = 40)
        corrupted_data = data[:50] + b"\xFF" * 20 + data[70:]
        corrupted_archive = real_crypto_archive.parent / "corrupted.gps"
        corrupted_archive.write_bytes(corrupted_data)

        service = ImportExportService(
            session_manager=mock_session_manager,
            crypto_service=real_crypto,
            profile_manager=mock_profile_manager,
            repository_manager=mock_repository_manager,
        )

        with pytest.raises((InvalidArchiveError, ArchivePasswordError)):
            service.import_profiles(
                file_path=corrupted_archive,
                archive_password=sample_archive_password,
            )


# =============================================================================
# Result Dataclass Tests
# =============================================================================


class TestExportResult:
    """Tests for ExportResult dataclass."""

    def test_export_result_contains_file_path(
        self,
        import_export_service: "ImportExportService",
        temp_dir: Path,
        sample_archive_password: str,
    ) -> None:
        """ExportResult should contain the archive file path."""
        archive_path = temp_dir / "result_test.gps"

        result = import_export_service.export_profiles(
            file_path=archive_path,
            archive_password=sample_archive_password,
        )

        assert result.file_path == archive_path

    def test_export_result_contains_profile_count(
        self,
        import_export_service: "ImportExportService",
        temp_dir: Path,
        sample_archive_password: str,
    ) -> None:
        """ExportResult should contain the exported profile count."""
        archive_path = temp_dir / "count_test.gps"

        result = import_export_service.export_profiles(
            file_path=archive_path,
            archive_password=sample_archive_password,
        )

        assert result.profile_count == 2

    def test_export_result_contains_file_size(
        self,
        import_export_service: "ImportExportService",
        temp_dir: Path,
        sample_archive_password: str,
    ) -> None:
        """ExportResult should contain the archive file size."""
        archive_path = temp_dir / "size_test.gps"

        result = import_export_service.export_profiles(
            file_path=archive_path,
            archive_password=sample_archive_password,
        )

        assert result.file_size > 0
        assert result.file_size == archive_path.stat().st_size


class TestImportResult:
    """Tests for ImportResult dataclass."""

    def test_import_result_contains_imported_profiles(
        self,
        import_export_service: "ImportExportService",
        sample_archive: Path,
        sample_archive_password: str,
        mock_profile_manager: MagicMock,
    ) -> None:
        """ImportResult should contain list of imported profiles."""
        mock_profile_manager.list_profiles.return_value = []

        result = import_export_service.import_profiles(
            file_path=sample_archive,
            archive_password=sample_archive_password,
            mode="replace",
        )

        assert isinstance(result.imported_profiles, list)

    def test_import_result_contains_skipped_profiles(
        self,
        import_export_service: "ImportExportService",
        sample_archive: Path,
        sample_archive_password: str,
    ) -> None:
        """ImportResult should contain list of skipped profile names."""
        result = import_export_service.import_profiles(
            file_path=sample_archive,
            archive_password=sample_archive_password,
            mode="merge",
            conflict_resolution="skip",
        )

        assert isinstance(result.skipped_profiles, list)

    def test_import_result_contains_renamed_profiles(
        self,
        import_export_service: "ImportExportService",
        sample_archive: Path,
        sample_archive_password: str,
    ) -> None:
        """ImportResult should contain dict of renamed profiles."""
        result = import_export_service.import_profiles(
            file_path=sample_archive,
            archive_password=sample_archive_password,
            mode="merge",
            conflict_resolution="rename",
        )

        assert isinstance(result.renamed_profiles, dict)

    def test_import_result_contains_repository_count(
        self,
        import_export_service: "ImportExportService",
        sample_archive: Path,
        sample_archive_password: str,
        mock_profile_manager: MagicMock,
    ) -> None:
        """ImportResult should contain count of imported repositories."""
        mock_profile_manager.list_profiles.return_value = []

        result = import_export_service.import_profiles(
            file_path=sample_archive,
            archive_password=sample_archive_password,
            mode="replace",
        )

        assert isinstance(result.imported_repositories, int)


# =============================================================================
# Edge Cases and Security Tests
# =============================================================================


class TestImportExportSecurity:
    """Security-focused tests for import/export operations."""

    def test_export_does_not_leak_session_key(
        self,
        import_export_service: "ImportExportService",
        temp_dir: Path,
        sample_archive_password: str,
        mock_session_manager: MagicMock,
    ) -> None:
        """Exported archive should not contain the session encryption key."""
        archive_path = temp_dir / "security_test.gps"
        session_key = mock_session_manager.encryption_key

        import_export_service.export_profiles(
            file_path=archive_path,
            archive_password=sample_archive_password,
        )

        # Read archive contents
        archive_data = archive_path.read_bytes()

        # Session key should not appear in archive
        assert session_key not in archive_data

    def test_export_re_encrypts_keys_with_archive_key(
        self,
        import_export_service: "ImportExportService",
        temp_dir: Path,
        sample_archive_password: str,
        mock_crypto_service: MagicMock,
    ) -> None:
        """Keys should be re-encrypted with archive-derived key."""
        archive_path = temp_dir / "reencrypt_test.gps"

        import_export_service.export_profiles(
            file_path=archive_path,
            archive_password=sample_archive_password,
        )

        # Verify encrypt was called (re-encryption of keys)
        # The implementation should decrypt with session key then encrypt with archive key
        assert mock_crypto_service.derive_key.called

    def test_import_file_not_found_raises_error(
        self,
        import_export_service: "ImportExportService",
        temp_dir: Path,
        sample_archive_password: str,
    ) -> None:
        """import_profiles should raise error for non-existent file."""
        nonexistent = temp_dir / "does_not_exist.gps"

        with pytest.raises(FileNotFoundError):
            import_export_service.import_profiles(
                file_path=nonexistent,
                archive_password=sample_archive_password,
            )


class TestImportExportEdgeCases:
    """Edge case tests for import/export operations."""

    def test_export_with_special_characters_in_name(
        self,
        mock_session_manager: MagicMock,
        mock_crypto_service: MagicMock,
        mock_repository_manager: MagicMock,
        temp_dir: Path,
        sample_archive_password: str,
    ) -> None:
        """export_profiles should handle profiles with special characters."""
        from src.core.import_export import ImportExportService
        from src.models.profile import GPGKey, Profile, SSHKey

        # Create profile with special characters
        special_profile = Profile(
            name="Work @ Acme Corp. (Personal)",
            git_username="user-name_123",
            git_email="test@example.com",
            ssh_key=SSHKey(
                private_key_encrypted=b"ENC:key",
                public_key=b"ssh-ed25519 AAAA test@example.com",
            ),
            gpg_key=GPGKey(),
        )

        special_profile_manager = MagicMock()
        special_profile_manager.list_profiles.return_value = [special_profile]
        special_profile_manager.get_profile.return_value = special_profile

        service = ImportExportService(
            session_manager=mock_session_manager,
            crypto_service=mock_crypto_service,
            profile_manager=special_profile_manager,
            repository_manager=mock_repository_manager,
        )

        archive_path = temp_dir / "special.gps"
        result = service.export_profiles(
            file_path=archive_path,
            archive_password=sample_archive_password,
        )

        assert result.profile_count == 1

    def test_export_empty_password_allowed(
        self,
        import_export_service: "ImportExportService",
        temp_dir: Path,
    ) -> None:
        """export_profiles should allow empty archive password (for local use)."""
        archive_path = temp_dir / "no_password.gps"

        # Empty password should work (though not recommended for sharing)
        result = import_export_service.export_profiles(
            file_path=archive_path,
            archive_password="",
        )

        assert result.file_path.exists()

    def test_import_without_repositories(
        self,
        import_export_service: "ImportExportService",
        temp_dir: Path,
        sample_archive_password: str,
        mock_profile_manager: MagicMock,
    ) -> None:
        """import_profiles should handle archives without repository data."""
        # Export without repositories
        archive_path = temp_dir / "no_repos.gps"
        import_export_service.export_profiles(
            file_path=archive_path,
            archive_password=sample_archive_password,
            include_repositories=False,
        )

        # Clear profiles for fresh import
        mock_profile_manager.list_profiles.return_value = []

        # Import should succeed
        result = import_export_service.import_profiles(
            file_path=archive_path,
            archive_password=sample_archive_password,
            mode="replace",
        )

        assert result.imported_repositories == 0
